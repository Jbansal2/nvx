//! The probes that the worker runs on its assembled root: named checks of a scenario, each of which
//! reports what it finds as [`Facts`].
//!
//! | Probe | Facts |
//! | --- | --- |
//! | `mounts` | For the image's mount, `distro`, the scratch's, `scratch`, and the overlay's, `root`: the number of mounts at its mount point, `NAME.count`, and of the topmost, its `NAME.type`, `NAME.source`, `NAME.options`, and `NAME.super`, the file system's own options |
//! | `contents` | The root's `os-release.id` and `root.mode`. It writes [`PROBE_FILE`] in the root, and reports what the root, `write.root`, the upper, `write.upper`, and the image, `write.lower`, hold at that name, and whether the image refuses a new file, `lower.write` |
//! | `cgroups` | The file system at the cgroups' parent, `parent.type`, and its `parent.subtree-control`; whether each cgroup exists, `agent.exists` and `workload.exists`; `agent.memory.low`, `workload.memory.max`, and `workload.pids.max`; the number of processes in each, `agent.processes` and `workload.processes`; and `user-namespaces`, the guest's limit of user namespaces, or `unavailable` without them |
//! | `processes` | For PID 1, `pid1`, the worker, `worker`, and PID 1's unrelated child, `sibling`: `NAME.pid`, and while the process exists, `NAME.state`, `NAME.ppid`, `NAME.root`, `NAME.cgroup`, `NAME.command`, and `NAME.namespaces`: `same` if it shares PID 1's, or the ones that differ |
//! | `hold` | It opens the root, and keeps it open until the worker ends, so that the teardown finds the root busy: `held`, the path that it holds |
//!
//! None takes arguments. A value that a probe cannot read is `absent` if its file does not exist,
//! and otherwise `unreadable: PROBLEM`.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;

use crate::probe::{Facts, Probe};

/// The file that the `contents` probe writes at the top of the root.
pub const PROBE_FILE: &str = ".runtime-adapter-probe";
/// What the `contents` probe writes in [`PROBE_FILE`].
pub const PROBE_CONTENTS: &str = "runtime-adapter";
/// The file that the `contents` probe tries to create at the top of the image.
const LOWER_FILE: &str = ".runtime-adapter-lower";
/// The mount table of the worker's mount namespace.
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// The guest's limit of user namespaces, which only a kernel with user namespaces has.
const USER_NAMESPACES: &str = "/proc/sys/user/max_user_namespaces";
/// The namespaces that the `processes` probe compares with PID 1's, of those that the guest's
/// kernel has.
const NAMESPACES: [&str; 7] = ["cgroup", "ipc", "mnt", "net", "pid", "user", "uts"];

/// What the probes check: the worker's root and cgroups, and PID 1's unrelated child.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The runtime directory, below which `nvx::guest::root` mounts the root: the image at
    /// `layers/distro`, the scratch, with the overlay's `upper` directory, at `scratch`, and the
    /// overlay, the root, at `rootfs`.
    pub runtime: &'a Path,
    /// The root, the overlay's mount point.
    pub root: &'a Path,
    /// The agent's cgroup.
    pub agent: &'a Path,
    /// The workload cgroup.
    pub workload: &'a Path,
    /// The process ID of PID 1's unrelated child, if PID 1 named one.
    pub sibling: Option<u32>,
}

impl Context<'_> {
    /// Returns the image's mount point.
    fn distro(&self) -> PathBuf {
        self.runtime.join("layers/distro")
    }

    /// Returns the scratch's mount point.
    fn scratch(&self) -> PathBuf {
        self.runtime.join("scratch")
    }
}

/// Runs `probe` with `context`, and returns its facts. `held` keeps the descriptors that a probe
/// keeps open until the worker ends.
///
/// Fails with the problem for a probe that the [module documentation](self) does not list, one
/// with arguments, and one that fails.
pub fn run(probe: &Probe, context: &Context<'_>, held: &mut Vec<File>) -> Result<Facts, String> {
    let name = probe.name();
    if !["mounts", "contents", "cgroups", "processes", "hold"].contains(&name) {
        return Err(format!("the worker runs no probe named {name}"));
    }
    if !probe.arguments().is_empty() {
        return Err(format!("the {name} probe takes no arguments"));
    }
    let facts = match name {
        "mounts" => mounts(context),
        "contents" => contents(context),
        "cgroups" => cgroups(context),
        "processes" => processes(context),
        _ => hold(context, held),
    };
    facts.map_err(|error| format!("the {name} probe failed: {error}"))
}

/// Runs the `mounts` probe.
fn mounts(context: &Context<'_>) -> io::Result<Facts> {
    let table = mount_table(&fs::read_to_string(MOUNTINFO)?)?;
    let mut facts = Facts::new();
    for (name, point) in [
        ("distro", context.distro()),
        ("scratch", context.scratch()),
        ("root", context.root.to_owned()),
    ] {
        let mounts = table
            .iter()
            .filter(|mount| mount.point == point)
            .collect::<Vec<_>>();
        facts.push(format!("{name}.count"), mounts.len().to_string());
        // Of the mounts at a point, the table lists the topmost last.
        if let Some(mount) = mounts.last() {
            facts.push(format!("{name}.type"), mount.kind.as_str());
            facts.push(format!("{name}.source"), mount.source.as_str());
            facts.push(format!("{name}.options"), mount.options.as_str());
            facts.push(format!("{name}.super"), mount.super_options.as_str());
        }
    }
    Ok(facts)
}

/// Runs the `contents` probe.
fn contents(context: &Context<'_>) -> io::Result<Facts> {
    let root = context.root;
    let mut facts = Facts::new();
    // The image's own file first: `/etc/os-release` may be a link that resolves outside the root.
    let identifier = ["usr/lib/os-release", "etc/os-release"]
        .iter()
        .find_map(|path| fs::read_to_string(root.join(path)).ok())
        .and_then(|text| os_release_id(&text).map(str::to_owned));
    facts.push("os-release.id", identifier.as_deref().unwrap_or("absent"));
    let mode = fs::metadata(root)?.permissions().mode() & 0o7777;
    facts.push("root.mode", format!("{mode:o}"));
    fs::write(root.join(PROBE_FILE), PROBE_CONTENTS)?;
    facts.push("write.root", read(&root.join(PROBE_FILE)));
    let upper = context.scratch().join("upper").join(PROBE_FILE);
    facts.push("write.upper", read(&upper));
    facts.push("write.lower", read(&context.distro().join(PROBE_FILE)));
    let lower = match File::create_new(context.distro().join(LOWER_FILE)) {
        Ok(_) => "allowed".to_owned(),
        Err(error) if error.raw_os_error() == Some(Errno::EROFS as i32) => "refused".to_owned(),
        Err(error) => format!("failed: {error}"),
    };
    facts.push("lower.write", lower);
    Ok(facts)
}

/// Runs the `cgroups` probe.
fn cgroups(context: &Context<'_>) -> io::Result<Facts> {
    let parent = context.agent.parent().unwrap_or(Path::new("/"));
    let table = mount_table(&fs::read_to_string(MOUNTINFO)?)?;
    let parent_type = table
        .iter()
        .rev()
        .find(|mount| mount.point == parent)
        .map_or("none", |mount| mount.kind.as_str());
    let mut facts = Facts::new();
    facts.push("parent.type", parent_type);
    facts.push(
        "parent.subtree-control",
        read(&parent.join("cgroup.subtree_control")),
    );
    for (name, cgroup) in [("agent", context.agent), ("workload", context.workload)] {
        let exists = if cgroup.is_dir() { "yes" } else { "no" };
        facts.push(format!("{name}.exists"), exists);
    }
    facts.push("agent.memory.low", read(&context.agent.join("memory.low")));
    for value in ["memory.max", "pids.max"] {
        facts.push(
            format!("workload.{value}"),
            read(&context.workload.join(value)),
        );
    }
    for (name, cgroup) in [("agent", context.agent), ("workload", context.workload)] {
        let processes = fs::read_to_string(cgroup.join("cgroup.procs"))?;
        facts.push(
            format!("{name}.processes"),
            processes.lines().count().to_string(),
        );
    }
    let user_namespaces = Path::new(USER_NAMESPACES);
    let limit = if user_namespaces.exists() {
        read(user_namespaces)
    } else {
        "unavailable".to_owned()
    };
    facts.push("user-namespaces", limit);
    Ok(facts)
}

/// Runs the `processes` probe.
fn processes(context: &Context<'_>) -> io::Result<Facts> {
    let init = namespaces(1)?;
    let mut facts = Facts::new();
    let processes = [
        ("pid1", Some(1)),
        ("worker", Some(std::process::id())),
        ("sibling", context.sibling),
    ];
    for (name, id) in processes {
        let Some(id) = id else {
            facts.push(format!("{name}.pid"), "none");
            continue;
        };
        facts.push(format!("{name}.pid"), id.to_string());
        let directory = PathBuf::from(format!("/proc/{id}"));
        let stat = match fs::read_to_string(directory.join("stat")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                facts.push(format!("{name}.state"), "gone");
                continue;
            }
            stat => stat?,
        };
        let (state, parent) = parse_stat(&stat).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the status of process {id} is malformed"),
            )
        })?;
        facts.push(format!("{name}.state"), state);
        facts.push(format!("{name}.ppid"), parent);
        let root = fs::read_link(directory.join("root"))?;
        facts.push(format!("{name}.root"), root.display().to_string());
        let cgroup = fs::read_to_string(directory.join("cgroup"))?;
        facts.push(
            format!("{name}.cgroup"),
            unified_cgroup(&cgroup).unwrap_or("none"),
        );
        let command = fs::read(directory.join("cmdline"))?;
        facts.push(format!("{name}.command"), command_text(&command));
        let differ = namespaces(id)?
            .into_iter()
            .zip(&init)
            .filter(|((_, own), (_, first))| own != first)
            .map(|((namespace, _), _)| namespace)
            .collect::<Vec<_>>();
        let shared = if differ.is_empty() {
            "same".to_owned()
        } else {
            format!("differ:{}", differ.join(","))
        };
        facts.push(format!("{name}.namespaces"), shared);
    }
    Ok(facts)
}

/// Runs the `hold` probe, which keeps its descriptor in `held`.
fn hold(context: &Context<'_>, held: &mut Vec<File>) -> io::Result<Facts> {
    held.push(File::open(context.root)?);
    let mut facts = Facts::new();
    facts.push("held", context.root.display().to_string());
    Ok(facts)
}

/// Returns the namespaces of the process `id`, each as its name and its identity, in the order
/// of [`NAMESPACES`], with `None` for one that the kernel does not have.
fn namespaces(id: u32) -> io::Result<Vec<(&'static str, Option<PathBuf>)>> {
    NAMESPACES
        .into_iter()
        .map(
            |namespace| match fs::read_link(format!("/proc/{id}/ns/{namespace}")) {
                Ok(identity) => Ok((namespace, Some(identity))),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((namespace, None)),
                Err(error) => Err(error),
            },
        )
        .collect()
}

/// Returns the trimmed contents of the file at `path`, `absent` if it does not exist, or
/// `unreadable: PROBLEM`.
fn read(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).trim().to_owned(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => "absent".to_owned(),
        Err(error) => format!("unreadable: {error}"),
    }
}

/// A mount of a mount table.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Mount {
    /// The mount point.
    point: PathBuf,
    /// The mount's options.
    options: String,
    /// The file system's type.
    kind: String,
    /// The mount's source.
    source: String,
    /// The file system's own options.
    super_options: String,
}

/// Parses a mount table in the format of `/proc/PID/mountinfo`, in its order:
/// `ID PARENT MAJOR:MINOR ROOT POINT OPTIONS [OPTIONAL...] - TYPE SOURCE SUPER`, with `\NNN` octal
/// escapes in its paths and source.
fn mount_table(table: &str) -> io::Result<Vec<Mount>> {
    table
        .lines()
        .map(|line| {
            let fields = line.split(' ').collect::<Vec<_>>();
            let separator = fields.iter().position(|field| *field == "-");
            let mount = match (separator, fields.as_slice()) {
                (Some(separator), [_, _, _, _, point, options, ..]) if separator >= 6 => {
                    match fields[separator + 1..] {
                        [kind, source, super_options] => Some(Mount {
                            point: PathBuf::from(OsString::from_vec(unescape(point))),
                            options: (*options).to_owned(),
                            kind: kind.to_owned(),
                            source: String::from_utf8_lossy(&unescape(source)).into_owned(),
                            super_options: super_options.to_owned(),
                        }),
                        _ => None,
                    }
                }
                _ => None,
            };
            mount.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the mount table has a malformed line: {line:?}"),
                )
            })
        })
        .collect()
}

/// Reverses the `\NNN` octal escapes of a field of a mount table.
fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut unescaped = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escape = bytes.get(index + 1..index + 4).and_then(|digits| {
            let octal = digits.iter().all(|digit| (b'0'..=b'7').contains(digit));
            let text = std::str::from_utf8(digits).ok()?;
            octal.then(|| u8::from_str_radix(text, 8).ok()).flatten()
        });
        match escape {
            Some(byte) if bytes[index] == b'\\' => {
                unescaped.push(byte);
                index += 4;
            }
            _ => {
                unescaped.push(bytes[index]);
                index += 1;
            }
        }
    }
    unescaped
}

/// Returns the state and the parent's process ID from a process's `/proc/PID/stat`, whose command
/// is parenthesized and may hold any character, `)` and spaces included.
fn parse_stat(stat: &str) -> Option<(&str, &str)> {
    let (_, rest) = stat.rsplit_once(')')?;
    let mut fields = rest.split_whitespace();
    Some((fields.next()?, fields.next()?))
}

/// Returns a process's cgroup of the unified hierarchy from its `/proc/PID/cgroup`: the path of
/// the line `0::PATH`.
fn unified_cgroup(cgroup: &str) -> Option<&str> {
    cgroup.lines().find_map(|line| line.strip_prefix("0::"))
}

/// Returns a process's command line from its `/proc/PID/cmdline`, whose arguments end with NULs,
/// with the arguments separated by spaces.
fn command_text(command: &[u8]) -> String {
    command
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Returns the `ID` of an `os-release` file, without its quotes.
fn os_release_id(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix("ID="))
        .map(|value| value.trim().trim_matches(['"', '\'']))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_table_is_read_with_its_escapes() {
        let table = "\
22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
41 30 254:0 / /run/a\\040b/layers/distro ro,relatime - erofs /dev/vda ro,user_xattr
42 30 254:16 / /run/a\\040b/scratch rw,nosuid,nodev,relatime - ext4 /dev/vdb rw
43 30 0:40 / /run/a\\040b/rootfs rw,nosuid,nodev,relatime - overlay overlay \
rw,lowerdir=/run/a\\040b/layers/distro,metacopy=on,xino=on
";
        let table = mount_table(table).unwrap();
        assert_eq!(table.len(), 4);
        assert_eq!(
            table[1],
            Mount {
                point: PathBuf::from("/run/a b/layers/distro"),
                options: "ro,relatime".to_owned(),
                kind: "erofs".to_owned(),
                source: "/dev/vda".to_owned(),
                super_options: "ro,user_xattr".to_owned(),
            }
        );
        assert_eq!(table[0].point, Path::new("/proc"));
        assert_eq!(table[3].kind, "overlay");
        assert_eq!(mount_table("").unwrap(), []);
        for line in [
            "1 2 3 4 5 6 - a b",
            "1 2 3 4 - a b c",
            "1 2 3 4 5 6 7 a b c",
        ] {
            let error = mount_table(line).unwrap_err();
            assert!(error.to_string().contains("malformed line"), "{line:?}");
        }
    }

    #[test]
    fn escapes_are_three_octal_digits() {
        assert_eq!(unescape("a\\040b\\134c"), b"a b\\c");
        assert_eq!(unescape("\\012\\011"), b"\n\t");
        // What starts no escape stays as it is.
        assert_eq!(unescape("a\\08b\\04"), b"a\\08b\\04");
        assert_eq!(unescape("\\"), b"\\");
    }

    #[test]
    fn process_records_are_read_as_the_kernel_writes_them() {
        assert_eq!(parse_stat("17 (a) b (c)) S 1 17 17 0 -1"), Some(("S", "1")));
        assert_eq!(parse_stat("17 (idle) R 1"), Some(("R", "1")));
        assert_eq!(parse_stat("17 (idle) R"), None);
        assert_eq!(parse_stat("17 idle R 1"), None);
        assert_eq!(unified_cgroup("0::/agent\n"), Some("/agent"));
        assert_eq!(unified_cgroup("1:name=x:/a\n0::/\n"), Some("/"));
        assert_eq!(unified_cgroup("1:name=x:/a\n"), None);
        assert_eq!(
            command_text(b"/sbin/runtime-adapter-guest\0idle\0"),
            "/sbin/runtime-adapter-guest idle"
        );
        assert_eq!(command_text(b""), "");
    }

    #[test]
    fn the_os_release_id_loses_its_quotes() {
        let text = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(os_release_id(text), Some("ubuntu"));
        assert_eq!(os_release_id("ID=\"alpine\"\n"), Some("alpine"));
        assert_eq!(os_release_id("ID='x'"), Some("x"));
        assert_eq!(os_release_id("NAME=x\n"), None);
    }

    #[test]
    fn unknown_probes_and_arguments_are_refused() {
        let context = Context {
            runtime: Path::new("/run/runtime-adapter"),
            root: Path::new("/run/runtime-adapter/rootfs"),
            agent: Path::new("/sys/fs/cgroup/agent"),
            workload: Path::new("/sys/fs/cgroup/workload"),
            sibling: None,
        };
        let mut held = Vec::new();
        let unknown = Probe::parse("mapping").unwrap();
        assert_eq!(
            run(&unknown, &context, &mut held),
            Err("the worker runs no probe named mapping".to_owned())
        );
        let with_argument = Probe::parse("hold /").unwrap();
        assert_eq!(
            run(&with_argument, &context, &mut held),
            Err("the hold probe takes no arguments".to_owned())
        );
        assert!(held.is_empty());
    }
}
