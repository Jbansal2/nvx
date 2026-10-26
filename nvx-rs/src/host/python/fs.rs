//! The path queries of Python's `pathlib.Path` that the sandbox launch profile still uses, as
//! CPython 3.14 performs them on Linux and Windows.
//!
//! - [`cwd`]: the current directory, as `Path.cwd()` gives it.
//! - [`resolve`]: `Path.resolve()`, which follows `os.path.realpath`: it resolves symbolic links
//!   component by component on POSIX, keeping the components that do not exist, and asks Windows
//!   for the final path of the longest existing prefix, dropping the `\\?\` prefix again.
//!
//! Paths must be valid Unicode: a link target or working directory that is not is an error,
//! where Python would decode it into surrogates.

use std::io;

use super::not_unicode;
use super::path::PurePath;

/// Returns `Path.cwd()`.
pub(crate) fn cwd() -> io::Result<PurePath> {
    let directory = std::env::current_dir()?;
    let text = directory
        .to_str()
        .ok_or_else(|| not_unicode("the current directory"))?;
    Ok(PurePath::native(text))
}

/// Returns `path.resolve()`: the absolute path of `path`, with symbolic links resolved and `..`
/// components removed, as `os.path.realpath(path)` gives it.
pub(crate) fn resolve(path: &PurePath) -> io::Result<PurePath> {
    imp::realpath(path.as_str()).map(|resolved| PurePath::native(&resolved))
}

#[cfg(unix)]
/// The POSIX implementation, on the standard library.
mod imp {
    use std::fs;
    use std::io;

    use super::not_unicode;

    /// Returns `posixpath.realpath(path)` in its non-strict mode: each component is resolved in
    /// turn, a symbolic link is replaced by its target, and a component that cannot be examined
    /// is kept as it is. A symbolic-link loop stops resolution at the link.
    pub(super) fn realpath(path: &str) -> io::Result<String> {
        // The unresolved components, last first. `None` marks the end of a link's target, and
        // is followed by the link's own path.
        let mut rest: Vec<Option<String>> = path
            .split('/')
            .rev()
            .map(|part| Some(part.to_owned()))
            .collect();
        let mut part_count = rest.len();
        let mut resolved = if path.starts_with('/') {
            "/".to_owned()
        } else {
            let directory = std::env::current_dir()?;
            directory
                .to_str()
                .ok_or_else(|| not_unicode("the current directory"))?
                .to_owned()
        };
        // Each link that has been seen, with its resolved target once known.
        let mut seen: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        while part_count > 0 {
            let Some(name) = rest.pop() else {
                break;
            };
            let Some(name) = name else {
                // The target of a link is resolved.
                if let Some(Some(link)) = rest.pop() {
                    seen.insert(link, Some(resolved.clone()));
                }
                continue;
            };
            part_count -= 1;
            if name.is_empty() || name == "." {
                continue;
            }
            if name == ".." {
                let end = resolved.rfind('/').unwrap_or(0);
                resolved.truncate(end);
                if resolved.is_empty() {
                    resolved.push('/');
                }
                continue;
            }
            let candidate = if resolved == "/" {
                format!("/{name}")
            } else {
                format!("{resolved}/{name}")
            };
            if candidate.contains('\0') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "embedded null byte",
                ));
            }
            let target = match fs::symlink_metadata(&candidate) {
                Ok(metadata) if !metadata.file_type().is_symlink() => {
                    resolved = candidate;
                    continue;
                }
                Ok(_) => match seen.get(&candidate) {
                    Some(Some(target)) => {
                        resolved = target.clone();
                        continue;
                    }
                    // A link whose resolution is in progress: a loop.
                    Some(None) => {
                        resolved = candidate;
                        continue;
                    }
                    None => fs::read_link(&candidate),
                },
                Err(error) => Err(error),
            };
            let Ok(target) = target else {
                // Errors are ignored: the component is kept as it is.
                resolved = candidate;
                continue;
            };
            let target = target
                .into_os_string()
                .into_string()
                .map_err(|_| not_unicode("a symbolic link's target"))?;
            if target.starts_with('/') {
                "/".clone_into(&mut resolved);
            }
            seen.insert(candidate.clone(), None);
            rest.push(Some(candidate));
            rest.push(None);
            let parts: Vec<&str> = target.split('/').collect();
            part_count += parts.len();
            rest.extend(parts.into_iter().rev().map(|part| Some(part.to_owned())));
        }
        Ok(resolved)
    }
}

#[cfg(windows)]
/// The Windows implementation, on the Win32 calls that CPython makes.
mod imp {
    use std::io;
    use std::path::Path;

    use super::super::path::{Flavor, windows_normpath};
    use super::super::windows as win32;

    /// Returns `ntpath.normcase(path)`: lowercase, with `\` separators.
    fn normcase(path: &str) -> String {
        path.replace('/', "\\").to_lowercase()
    }

    /// Returns `ntpath.dirname(path)`.
    fn dirname(path: &str) -> String {
        Flavor::Windows.split(path).0
    }

    /// Returns whether `error` is one of the Win32 errors in `codes`.
    fn is_error(error: &io::Error, codes: &[i32]) -> bool {
        error
            .raw_os_error()
            .is_some_and(|code| codes.contains(&code))
    }

    /// Follows the links at `path` as `ntpath._readlink_deep` does, stopping at a path that is
    /// not a link, at a loop, or at an error that ends resolution.
    fn readlink_deep(path: &str) -> io::Result<String> {
        const STOP: [i32; 12] = [1, 2, 3, 5, 21, 32, 50, 67, 87, 4390, 4392, 4393];
        let mut path = path.to_owned();
        let mut seen = std::collections::HashSet::new();
        while seen.insert(normcase(&path)) {
            let old = path.clone();
            match win32::read_link(Path::new(&path)) {
                Ok(Some(target)) => {
                    path = target;
                    if !Flavor::Windows.is_absolute(&path) {
                        // A relative target resolves against the link's own directory, but
                        // only a symbolic link has one.
                        if !Path::new(&old).is_symlink() {
                            path = old;
                            break;
                        }
                        path = windows_normpath(&Flavor::Windows.join(&dirname(&old), &path));
                    }
                }
                // A reparse point that is not a link.
                Ok(None) => break,
                Err(error) if is_error(&error, &STOP) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(path)
    }

    /// Resolves as much of `path` as exists and appends the rest, as
    /// `ntpath._getfinalpathname_nonstrict` does.
    fn final_path_name_nonstrict(path: &str) -> io::Result<String> {
        const STOP: [i32; 16] = [
            1, 2, 3, 5, 21, 32, 50, 53, 65, 67, 87, 123, 161, 1005, 1920, 1921,
        ];
        const BY_NAME: [i32; 7] = [1, 5, 32, 50, 87, 1920, 1921];
        let mut path = path.to_owned();
        let mut tail = String::new();
        while !path.is_empty() {
            let error = match win32::final_path_name(Path::new(&path)) {
                Ok(resolved) => {
                    return Ok(if tail.is_empty() {
                        resolved
                    } else {
                        Flavor::Windows.join(&resolved, &tail)
                    });
                }
                Err(error) if is_error(&error, &STOP) => error,
                Err(error) => return Err(error),
            };
            // Windows could not resolve the path: follow its links ourselves.
            match readlink_deep(&path) {
                Ok(target) if target != path => {
                    return Ok(if tail.is_empty() {
                        target
                    } else {
                        Flavor::Windows.join(&target, &tail)
                    });
                }
                _ => {}
            }
            let (head, name) = if is_error(&error, &BY_NAME) {
                // Read the real name of the file without opening it.
                match win32::find_first_file_name(Path::new(&path)) {
                    Ok(name) => (Flavor::Windows.split(&path).0, name),
                    Err(_) => Flavor::Windows.split(&path),
                }
            } else {
                Flavor::Windows.split(&path)
            };
            path = head;
            if !path.is_empty() && name.is_empty() {
                return Ok(format!("{path}{tail}"));
            }
            tail = if tail.is_empty() {
                name
            } else {
                Flavor::Windows.join(&name, &tail)
            };
        }
        Ok(tail)
    }

    /// Returns `ntpath.realpath(path)` in its non-strict mode.
    pub(super) fn realpath(path: &str) -> io::Result<String> {
        const PREFIX: &str = "\\\\?\\";
        const UNC_PREFIX: &str = "\\\\?\\UNC\\";
        let mut path = windows_normpath(path);
        if normcase(&path) == "nul" {
            return Ok("\\\\.\\NUL".to_owned());
        }
        let had_prefix = path.starts_with(PREFIX);
        if !had_prefix && !Flavor::Windows.is_absolute(&path) {
            let directory = std::env::current_dir()?;
            let directory = directory
                .to_str()
                .ok_or_else(|| super::not_unicode("the current directory"))?;
            path = Flavor::Windows.join(directory, &path);
        }
        if path.contains('\0') {
            // Python cannot pass the path to Windows and returns it as it is.
            return Ok(windows_normpath(&path));
        }
        let initial_error = match win32::final_path_name(Path::new(&path)) {
            Ok(resolved) => {
                path = resolved;
                None
            }
            Err(error) => {
                let code = error.raw_os_error();
                path = final_path_name_nonstrict(&path)?;
                code
            }
        };
        if !had_prefix && path.starts_with(PREFIX) {
            let stripped = match path.strip_prefix(UNC_PREFIX) {
                Some(rest) => format!("\\\\{rest}"),
                None => path[PREFIX.len()..].to_owned(),
            };
            // Drop the prefix if the path without it resolves to the same path, or if neither
            // exists for the same reason.
            match win32::final_path_name(Path::new(&stripped)) {
                Ok(resolved) if resolved == path => path = stripped,
                Ok(_) => {}
                Err(error) if error.raw_os_error() == initial_error.or(Some(0)) => {
                    path = stripped;
                }
                Err(_) => {}
            }
        }
        Ok(path)
    }
}

#[cfg(not(any(unix, windows)))]
/// Hosts other than POSIX and Windows resolve no paths.
mod imp {
    use std::io;

    pub(super) fn realpath(_path: &str) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported host",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn resolve_keeps_missing_components_and_follows_links() {
        let directory = tempfile::tempdir().unwrap();
        let root = resolve(&PurePath::native(directory.path().to_str().unwrap())).unwrap();
        assert!(root.is_absolute());
        let target = root.join("target");
        fs::create_dir(target.as_str()).unwrap();
        assert_eq!(resolve(&root.join("target")).unwrap(), target);
        assert_eq!(
            resolve(&root.join("missing/deeper")).unwrap(),
            root.join("missing").join("deeper")
        );
        assert_eq!(resolve(&root.join("target/../target")).unwrap(), target);
        let link = root.join("link");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(target.as_str(), link.as_str());
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(target.as_str(), link.as_str());
        if linked.is_ok() {
            assert_eq!(resolve(&link).unwrap(), target);
            assert_eq!(resolve(&link.join("child")).unwrap(), target.join("child"));
        }
    }
}
