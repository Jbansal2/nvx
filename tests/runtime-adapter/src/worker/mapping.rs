//! The probes that map beneath the worker's assembled root, as an adapter maps the host paths of
//! its sandboxes: through the root itself, with `nvx::guest::root::Root::map`, which checks the
//! targets against the container root's reserved set, and through mappers of the adapter's own,
//! `nvx::guest::mappings::Mapper`, with reserved sets of its choice. Each probe writes its
//! sources below `/tmp/runtime-adapter-sources`, on the guest's tmpfs, in place of the guest's
//! mount of a host's export: a directory `dir`, which holds the file `marker` and the empty
//! directory `inner`; a file `file.txt`; and an empty directory `out`. The links that the probes
//! plant in the root lead to `/tmp/runtime-adapter-outside`, an empty directory outside it.
//!
//! | Probe | Facts |
//! | --- | --- |
//! | `map` | Through the root, zero mappings, `zero`, and the mounts below the root then, `zero.mounts`; then a table, `table`: `dir` read-only at `/srv/maps/dir`, `dir/inner` read-write at `/srv/maps/dir/inner`, inside the first, `file.txt` read-only at `/srv/maps/file.txt`, and `out` read-write at `/srv/maps/out`. The mount points below the root, in the mount table's order, `mounts`, and of each mapping, `dir`, `inner`, `file`, and `out`, the options, `NAME.options`, and whether a write is `allowed` or `refused`, `NAME.write`, with what a write reached in the source, `NAME.source`, and what a read found, `NAME.read`. Whether the overlay's upper holds the created directory `srv/maps`, `upper.directory`, and the created empty file `srv/maps/file.txt`, `upper.file`; and whether the root is latched, `latched` |
//! | `map-refused` | Through the root, a mapping whose target is below the link `/srv/link`, `through-link`; whether the root is latched then, `latched`; a later mapping at `/srv/later`, `later`, and whether its target exists, `later.target`; the number of mounts below the root, `mounts`, and of entries in the directory outside it, `outside` |
//! | `map-checks` | Through a new mapper for each check: a link at each component of `/srv/checks/tN/a/b/new`, `link.a`, `link.b`, and `link.new`, and a link to `..`, `link.up`; magic links of a procfs that it mounts at `/srv/checks/proc`, then unmounts, `magic.self`, `magic.thread-self`, `magic.root`, `magic.cwd`, and `magic.fd`; a directory onto a file, `kind.directory`, and a file onto a directory, `kind.file`; through one mapper, a mapping onto a file that an earlier one shows, `nested.onto`, one that would create a target inside it, `nested.create`, whether that reached the source, `nested.source`, and its teardown, `nested.teardown`; the runtime's reserved targets, `reserved.run`, `reserved.run-nvx`, `reserved.time`, and `reserved.time-below`, the container root's, `reserved.proc`, `reserved.sys`, `reserved.dev`, `reserved.agent`, `reserved.machine-id`, and `reserved.etc`, and those of a set that the adapter chooses, the tree `/srv/adapter` and the path `/srv/checks/exact`: `reserved.adapter-tree`, `reserved.adapter-ancestor`, `reserved.adapter-path`, and `reserved.adapter-below`, with whether the refused ones created anything, `reserved.created`. A read-only mapping attached and unmounted again and again while another thread tries to open its file for writing: the attaches, `read-only.attaches`, their flags, `read-only.flags`, whether the file was ever writable, `read-only.writable`, and the source's file afterwards, `read-only.source`. Finally the entries and the mounts of the directory outside the root, `outside.entries` and `outside.mounts`, and the mounts that the checks left below `/srv/checks`, `left` |
//!
//! A check's outcome is `applied`, or why the mapper refused the mapping: `link` for a link at the
//! component that the check expects, and otherwise the kind of the error, such as `reserved` or
//! `target-kind`, with the path that it names, if any. None of the probes takes arguments.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::thread;

use nix::errno::Errno;
use nix::mount::{self, MsFlags};
use nvx::guest::mappings::{
    Access, InvalidMapping, Mapper, Mapping, MappingError, Reserved, SourceRoot, TargetRoot,
};
use nvx::guest::root::{self, Root};

use super::probes::{self, Context};
use crate::probe::{Facts, Probe};

/// The names of the probes of this module, which the worker runs with its root.
pub const PROBES: [&str; 3] = ["map", "map-refused", "map-checks"];

/// The directory below which each probe writes its sources, in a directory of its name.
const SOURCES: &str = "/tmp/runtime-adapter-sources";
/// The directory outside the root to which the links that the probes plant lead.
const OUTSIDE: &str = "/tmp/runtime-adapter-outside";
/// What the probes write through writable mappings.
const WRITTEN: &str = "runtime-adapter";
/// The number of times that `map-checks` attaches a read-only mapping, and unmounts it again,
/// while another thread tries to open its file for writing.
const READ_ONLY_ATTACHES: usize = 200;

/// Runs `probe`, one of [`PROBES`], with `context` and the worker's `root`, and returns its facts.
///
/// Fails with the problem for another probe, one with arguments, and one that fails.
pub fn run(probe: &Probe, context: &Context<'_>, root: &mut Root) -> Result<Facts, String> {
    let name = probe.name();
    if !PROBES.contains(&name) {
        return Err(format!("the worker runs no probe named {name}"));
    }
    if !probe.arguments().is_empty() {
        return Err(format!("the {name} probe takes no arguments"));
    }
    let facts = match name {
        "map" => map(context, root),
        "map-refused" => map_refused(context, root),
        _ => map_checks(context),
    };
    facts.map_err(|error| format!("the {name} probe failed: {error}"))
}

/// Runs the `map` probe.
fn map(context: &Context<'_>, root: &mut Root) -> io::Result<Facts> {
    let (sources, source) = sources("map")?;
    let mut facts = Facts::new();
    facts.push("zero", outcome(root.map(&source, &[])));
    facts.push("zero.mounts", mounts_below(context.root)?.len().to_string());
    let table = [
        mapping("dir", "/srv/maps/dir", Access::ReadOnly)?,
        mapping("dir/inner", "/srv/maps/dir/inner", Access::ReadWrite)?,
        mapping("file.txt", "/srv/maps/file.txt", Access::ReadOnly)?,
        mapping("out", "/srv/maps/out", Access::ReadWrite)?,
    ];
    facts.push("table", outcome(root.map(&source, &table)));
    let mounts = mounts_below(context.root)?
        .iter()
        .map(|(point, _)| in_root(context.root, point))
        .collect::<Vec<_>>();
    facts.push("mounts", mounts.join(","));
    let target = |path: &str| context.root.join(path);
    for (name, path) in [
        ("dir", "srv/maps/dir"),
        ("inner", "srv/maps/dir/inner"),
        ("file", "srv/maps/file.txt"),
        ("out", "srv/maps/out"),
    ] {
        facts.push(format!("{name}.options"), options_at(&target(path))?);
    }
    facts.push("dir.read", probes::read(&target("srv/maps/dir/marker")));
    facts.push("dir.write", create(&target("srv/maps/dir/new")));
    facts.push("inner.write", create(&target("srv/maps/dir/inner/new")));
    facts.push("inner.source", probes::read(&sources.join("dir/inner/new")));
    facts.push("file.read", probes::read(&target("srv/maps/file.txt")));
    facts.push("file.write", open_for_writing(&target("srv/maps/file.txt")));
    facts.push("out.write", create(&target("srv/maps/out/new")));
    facts.push("out.source", probes::read(&sources.join("out/new")));
    let upper = context.runtime.join("scratch/upper/srv/maps");
    facts.push("upper.directory", yes(upper.is_dir()));
    let file = fs::symlink_metadata(upper.join("file.txt"));
    facts.push(
        "upper.file",
        yes(file.is_ok_and(|file| file.is_file() && file.len() == 0)),
    );
    facts.push("latched", yes(root.is_latched()));
    Ok(facts)
}

/// Runs the `map-refused` probe.
fn map_refused(context: &Context<'_>, root: &mut Root) -> io::Result<Facts> {
    let (_, source) = sources("map-refused")?;
    let outside = outside()?;
    symlink(&outside, context.root.join("srv/link"))?;
    let mut facts = Facts::new();
    let through = mapping("dir", "/srv/link/escape", Access::ReadOnly)?;
    facts.push("through-link", outcome(root.map(&source, &[through])));
    facts.push("latched", yes(root.is_latched()));
    let later = mapping("dir", "/srv/later", Access::ReadOnly)?;
    facts.push("later", outcome(root.map(&source, &[later])));
    facts.push("later.target", exists(&context.root.join("srv/later")));
    facts.push("mounts", mounts_below(context.root)?.len().to_string());
    facts.push("outside", fs::read_dir(&outside)?.count().to_string());
    Ok(facts)
}

/// Runs the `map-checks` probe.
fn map_checks(context: &Context<'_>) -> io::Result<Facts> {
    let (sources, source) = sources("map-checks")?;
    let outside = outside()?;
    let base = context.root.join("srv/checks");
    fs::create_dir_all(&base)?;
    let checks = Checks {
        root: context.root,
        source: &source,
    };
    let mut facts = Facts::new();

    // A link at each component in turn, to the directory outside the root, and one to `..`.
    let components = ["a", "b", "new"];
    for (index, link) in components.iter().enumerate() {
        let mut directory = base.join(format!("t{index}"));
        directory.extend(&components[..index]);
        fs::create_dir_all(&directory)?;
        symlink(&outside, directory.join(link))?;
        let target = format!("/srv/checks/t{index}/{}", components.join("/"));
        let linked = format!("/srv/checks/t{index}/{}", components[..=index].join("/"));
        let found = checks.one(Reserved::default(), "dir", &target)?;
        facts.push(format!("link.{link}"), at_link(found, &linked));
    }
    symlink("..", base.join("up"))?;
    let found = checks.one(Reserved::default(), "dir", "/srv/checks/up/new")?;
    facts.push("link.up", at_link(found, "/srv/checks/up"));

    // Magic links of a procfs in the root, which comes off again whatever the checks found.
    let proc = base.join("proc");
    fs::create_dir(&proc)?;
    mount::mount(
        Some("proc"),
        &proc,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    let held = File::open(&outside);
    let magic = held.and_then(|held| {
        let process = std::process::id();
        let descriptor = held.as_raw_fd();
        [
            ("self", "/srv/checks/proc/self".to_owned()),
            ("thread-self", "/srv/checks/proc/thread-self".to_owned()),
            ("root", format!("/srv/checks/proc/{process}/root")),
            ("cwd", format!("/srv/checks/proc/{process}/cwd")),
            ("fd", format!("/srv/checks/proc/{process}/fd/{descriptor}")),
        ]
        .into_iter()
        .map(|(name, link)| {
            let found = checks.one(Reserved::default(), "dir", &format!("{link}/new"))?;
            Ok((name, at_link(found, &link)))
        })
        .collect::<io::Result<Vec<_>>>()
    });
    mount::umount(&proc)?;
    for (name, found) in magic? {
        facts.push(format!("magic.{name}"), found);
    }

    // Kinds.
    fs::write(base.join("plain"), "")?;
    fs::create_dir(base.join("directory"))?;
    let directory_on_file = checks.one(Reserved::default(), "dir", "/srv/checks/plain")?;
    facts.push("kind.directory", directory_on_file);
    let file_on_directory = checks.one(Reserved::default(), "file.txt", "/srv/checks/directory")?;
    facts.push("kind.file", file_on_directory);

    // A mapping may go onto what an earlier one shows, but creates nothing inside it.
    let mut nested = checks.mapper(Reserved::default())?;
    let onto = [
        mapping("dir", "/srv/checks/m", Access::ReadWrite)?,
        mapping("file.txt", "/srv/checks/m/marker", Access::ReadOnly)?,
    ];
    facts.push("nested.onto", applied(&mut nested, &source, &onto));
    let inside = [mapping("dir/inner", "/srv/checks/m/new", Access::ReadOnly)?];
    facts.push("nested.create", applied(&mut nested, &source, &inside));
    facts.push("nested.source", exists(&sources.join("dir/new")));
    facts.push("nested.teardown", torn_down(nested));

    // The runtime's reserved targets, the container root's, and a set of the adapter's.
    for (name, target) in [
        ("run", "/run"),
        ("run-nvx", "/run/nvx"),
        ("time", "/run/nvx/time"),
        ("time-below", "/run/nvx/time/x"),
    ] {
        let found = checks.one(Reserved::default(), "dir", target)?;
        facts.push(format!("reserved.{name}"), found);
    }
    for (name, target) in [
        ("proc", "/proc/x"),
        ("sys", "/sys"),
        ("dev", "/dev"),
        ("agent", "/.nvx-agent"),
        ("machine-id", "/etc/machine-id"),
        ("etc", "/etc"),
    ] {
        let found = checks.one(Reserved::container_root(), "dir", target)?;
        facts.push(format!("reserved.{name}"), found);
    }
    for (name, target) in [
        ("adapter-tree", "/srv/adapter/x"),
        ("adapter-ancestor", "/srv"),
        ("adapter-path", "/srv/checks/exact"),
        ("adapter-below", "/srv/checks/exact/below"),
    ] {
        let adapter = Reserved::new(["/srv/adapter"], ["/srv/checks/exact"]).map_err(invalid)?;
        let found = checks.one(adapter, "dir", target)?;
        facts.push(format!("reserved.{name}"), found);
    }
    facts.push(
        "reserved.created",
        exists(&context.root.join("srv/adapter")),
    );

    let (attaches, flags, writable) = checks.read_only(&base.join("ro"))?;
    facts.push("read-only.attaches", attaches.to_string());
    facts.push("read-only.flags", flags);
    facts.push("read-only.writable", writable);
    facts.push(
        "read-only.source",
        probes::read(&sources.join("dir/marker")),
    );

    facts.push(
        "outside.entries",
        fs::read_dir(&outside)?.count().to_string(),
    );
    facts.push("outside.mounts", mounts_below(&outside)?.len().to_string());
    facts.push("left", mounts_below(&base)?.len().to_string());
    Ok(facts)
}

/// The checks of `map-checks`, each with a mapper of its own beneath the root.
struct Checks<'a> {
    /// The root, the overlay's mount point.
    root: &'a Path,
    /// The root of the probe's sources.
    source: &'a SourceRoot,
}

impl Checks<'_> {
    /// Returns a new mapper beneath the root, with `reserved`.
    fn mapper(&self, reserved: Reserved) -> io::Result<Mapper> {
        Ok(Mapper::new(TargetRoot::open(self.root)?, reserved))
    }

    /// Applies the read-write mapping of `source` at `target` with a new mapper with `reserved`,
    /// tears down what it attached, and returns its outcome.
    fn one(&self, reserved: Reserved, source: &str, target: &str) -> io::Result<String> {
        let mut mapper = self.mapper(reserved)?;
        let found = applied(
            &mut mapper,
            self.source,
            &[mapping(source, target, Access::ReadWrite)?],
        );
        mapper.teardown().map_err(io::Error::other)?;
        Ok(found)
    }

    /// Attaches `dir` read-only at `target` and unmounts it again, [`READ_ONLY_ATTACHES`] times,
    /// while another thread tries to open its `marker` for writing, and returns the number of
    /// attaches, their flags, `ro,nosuid,nodev` if each had them, and whether the file was ever
    /// `writable` or `never`.
    fn read_only(&self, target: &Path) -> io::Result<(usize, String, &'static str)> {
        let relative = in_root(self.root, target);
        let marker = target.join("marker");
        let stop = Arc::new(AtomicBool::new(false));
        let wrote = Arc::new(AtomicBool::new(false));
        // The thread's attempts hold the lock, which a teardown takes, so that no attempt keeps
        // the mapping busy while it is unmounted.
        let attempts = Arc::new(RwLock::new(()));
        let racer = {
            let (stop, wrote, attempts) = (stop.clone(), wrote.clone(), attempts.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _attempt = attempts.read().unwrap_or_else(PoisonError::into_inner);
                    if OpenOptions::new().write(true).open(&marker).is_ok() {
                        wrote.store(true, Ordering::Relaxed);
                    }
                }
            })
        };
        let mut attached = 0;
        let mut missing = None;
        let attached_all = (|| -> io::Result<()> {
            for _ in 0..READ_ONLY_ATTACHES {
                let mut mapper = self.mapper(Reserved::default())?;
                let mapping = mapping("dir", &relative, Access::ReadOnly)?;
                mapper
                    .apply(self.source, &[mapping])
                    .map_err(io::Error::other)?;
                attached += 1;
                let options = options_at(target)?;
                let found = options.split(',').collect::<Vec<_>>();
                if !["ro", "nosuid", "nodev"]
                    .iter()
                    .all(|flag| found.contains(flag))
                {
                    missing.get_or_insert_with(|| options.clone());
                }
                let _teardown = attempts.write().unwrap_or_else(PoisonError::into_inner);
                mapper.teardown().map_err(io::Error::other)?;
            }
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        racer
            .join()
            .map_err(|_| io::Error::other("the writing thread panicked"))?;
        attached_all?;
        let flags = match missing {
            None => "ro,nosuid,nodev".to_owned(),
            Some(options) => format!("missing: {options}"),
        };
        let writable = if wrote.load(Ordering::Relaxed) {
            "writable"
        } else {
            "never"
        };
        Ok((attached, flags, writable))
    }
}

/// Writes the sources of the probe `name` below [`SOURCES`], as the
/// [module documentation](self) describes, and returns their directory and root.
fn sources(name: &str) -> io::Result<(PathBuf, SourceRoot)> {
    let directory = Path::new(SOURCES).join(name);
    fs::create_dir_all(directory.join("dir/inner"))?;
    fs::create_dir_all(directory.join("out"))?;
    fs::write(directory.join("dir/marker"), "source")?;
    fs::write(directory.join("file.txt"), "file")?;
    let root = SourceRoot::open(&directory)?;
    Ok((directory, root))
}

/// Creates [`OUTSIDE`], if it does not exist, and returns it.
fn outside() -> io::Result<PathBuf> {
    fs::create_dir_all(OUTSIDE)?;
    Ok(PathBuf::from(OUTSIDE))
}

/// Returns the mapping of `source` at `target` with `access`.
fn mapping(source: &str, target: &str, access: Access) -> io::Result<Mapping> {
    Mapping::new(source, target, access).map_err(invalid)
}

/// Returns `error`, a mapping that a probe names, as an I/O error.
fn invalid(error: InvalidMapping) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

/// Returns the outcome of a root's mapping: `applied`, or why the root refused it.
fn outcome(mapped: Result<(), root::Error>) -> String {
    match mapped {
        Ok(()) => "applied".to_owned(),
        Err(root::Error::Mapping { error, .. }) => refusal(&error),
        Err(error) => format!("failed: {error}"),
    }
}

/// Applies `mappings` from `source` with `mapper`, and returns `applied`, or why it refused one.
fn applied(mapper: &mut Mapper, source: &SourceRoot, mappings: &[Mapping]) -> String {
    match mapper.apply(source, mappings) {
        Ok(()) => "applied".to_owned(),
        Err(error) => refusal(error.error()),
    }
}

/// Returns `complete` once `mapper`'s teardown unmounted every mapping, or the failures.
fn torn_down(mapper: Mapper) -> String {
    match mapper.teardown() {
        Ok(()) => "complete".to_owned(),
        Err(error) => format!("failed: {error}"),
    }
}

/// Returns the kind of `error`, with the path that it names, if any.
fn refusal(error: &MappingError) -> String {
    let at = |kind: &str, path: &Path| format!("{kind} {}", path.display());
    match error {
        MappingError::Latched => "latched".to_owned(),
        MappingError::Reserved => "reserved".to_owned(),
        MappingError::Overlap { mapped } => at("overlap", mapped),
        MappingError::SourceKind => "source-kind".to_owned(),
        MappingError::Link { path } => at("link", path),
        MappingError::NotDirectory { path } => at("not-directory", path),
        MappingError::TargetKind => "target-kind".to_owned(),
        MappingError::Foreign { path } => at("foreign", path),
        MappingError::MountPoint => "mount-point".to_owned(),
        MappingError::Moved { .. } => format!("moved: {error}"),
        MappingError::System { .. } => format!("system: {error}"),
        error => format!("other: {error}"),
    }
}

/// Returns `link` if `found` is a refusal at the link `linked`, and otherwise `found`.
fn at_link(found: String, linked: &str) -> String {
    if found == format!("link {linked}") {
        "link".to_owned()
    } else {
        found
    }
}

/// Returns `path`, a path below `root`, as an absolute path in the root.
fn in_root(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    format!("/{}", relative.display())
}

/// Returns the mounts below `path`, not at it, in the mount table's order: each mount point, and
/// its options.
fn mounts_below(path: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let table = probes::mount_table(&fs::read_to_string(probes::MOUNTINFO)?)?;
    Ok(table
        .into_iter()
        .filter(|mount| mount.point.starts_with(path) && mount.point != path)
        .map(|mount| (mount.point, mount.options))
        .collect())
}

/// Returns the options of the topmost mount at `path`, or `none`.
fn options_at(path: &Path) -> io::Result<String> {
    let table = probes::mount_table(&fs::read_to_string(probes::MOUNTINFO)?)?;
    // Of the mounts at a point, the table lists the topmost last.
    Ok(table
        .iter()
        .rev()
        .find(|mount| mount.point == path)
        .map_or_else(|| "none".to_owned(), |mount| mount.options.clone()))
}

/// Creates the file `path` with [`WRITTEN`], and returns `allowed`, `refused` if its file system
/// is read-only, or the failure.
fn create(path: &Path) -> String {
    written(fs::write(path, WRITTEN))
}

/// Opens the existing file `path` for writing, and returns `allowed`, `refused` if its file
/// system is read-only, or the failure.
fn open_for_writing(path: &Path) -> String {
    written(OpenOptions::new().write(true).open(path).map(drop))
}

/// Returns the outcome of a write: `allowed`, `refused` for a read-only file system, or the
/// failure.
fn written(result: io::Result<()>) -> String {
    match result {
        Ok(()) => "allowed".to_owned(),
        Err(error) if error.raw_os_error() == Some(Errno::EROFS as i32) => "refused".to_owned(),
        Err(error) => format!("failed: {error}"),
    }
}

/// Returns `exists` if something is at `path`, without following a final link, and otherwise
/// `absent`.
fn exists(path: &Path) -> &'static str {
    if fs::symlink_metadata(path).is_ok() {
        "exists"
    } else {
        "absent"
    }
}

/// Returns `yes` or `no`.
fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_name_their_kind_and_path() {
        assert_eq!(refusal(&MappingError::Reserved), "reserved");
        assert_eq!(refusal(&MappingError::TargetKind), "target-kind");
        let link = MappingError::Link {
            path: PathBuf::from("/srv/link"),
        };
        assert_eq!(refusal(&link), "link /srv/link");
        assert_eq!(at_link(refusal(&link), "/srv/link"), "link");
        assert_eq!(at_link(refusal(&link), "/srv"), "link /srv/link");
        let foreign = MappingError::Foreign {
            path: PathBuf::from("/m/new"),
        };
        assert_eq!(refusal(&foreign), "foreign /m/new");
        assert_eq!(
            in_root(Path::new("/run/a/rootfs"), Path::new("/run/a/rootfs/srv/x")),
            "/srv/x"
        );
    }
}
