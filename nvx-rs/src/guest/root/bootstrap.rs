//! The guest's bootstrap: the agent's and the workload's sibling cgroups, and user namespaces.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use super::Error;
use super::kernel::{Kernel, Paths, SystemKernel};
use crate::guest::cgroup::{ExecutionCgroup, Layout};
use crate::guest::parse::parse_decimal;
use crate::guest::sys::{self, Errno, MountFlags};

/// The flag of a kernel thread among a process's flags in `/proc/PID/stat`: Linux's
/// `PF_KTHREAD`.
const KERNEL_THREAD: u64 = 0x0020_0000;
/// The most passes that the placement makes over the parent cgroup's processes. A process that a
/// moved one starts meanwhile starts in the parent too, and the next pass moves it.
const PLACEMENT_PASSES: usize = 16;
/// The sysctl, below procfs, of the user namespaces that each user may create.
const USER_NAMESPACES: &str = "sys/user/max_user_namespaces";

/// The resource values that [`bootstrap`] applies, each only when the caller gives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Resources {
    /// The agent's `memory.low`, in bytes: memory of the agent's cgroup that the kernel reclaims
    /// only when no unprotected memory is left.
    pub agent_memory_low: Option<u64>,
    /// The workload cgroup's `memory.max`, in bytes.
    pub workload_memory_max: Option<u64>,
    /// The workload cgroup's `pids.max`: the most processes in it and below it.
    pub workload_pids_max: Option<u64>,
}

impl Resources {
    /// Returns whether a value needs the `memory` controller.
    fn need_memory(&self) -> bool {
        self.agent_memory_low.is_some() || self.workload_memory_max.is_some()
    }
}

/// A step of [`bootstrap`], which an [`Error::Bootstrap`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BootstrapStep {
    /// Checking that the layout's cgroups are siblings.
    Layout,
    /// Setting `user.max_user_namespaces` to 0.
    UserNamespaces,
    /// Mounting the cgroup v2 hierarchy at the cgroups' parent.
    Hierarchy,
    /// Creating the agent's cgroup.
    AgentCgroup,
    /// Finding the parent cgroup's processes, and moving them into the agent's cgroup.
    Placement,
    /// Enabling the controllers of the resource values in the parent's `cgroup.subtree_control`.
    Controllers,
    /// Writing the agent's `memory.low`.
    AgentMemoryLow,
    /// Creating the workload cgroup.
    WorkloadCgroup,
    /// Writing the workload cgroup's `memory.max`.
    WorkloadMemoryMax,
    /// Writing the workload cgroup's `pids.max`.
    WorkloadPidsMax,
}

impl fmt::Display for BootstrapStep {
    /// Writes the step as the verb phrase of a failure: `failed to {step}`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Layout => "check that the agent's and the workload cgroups are siblings",
            Self::UserNamespaces => "disable user namespaces",
            Self::Hierarchy => "mount the cgroup hierarchy",
            Self::AgentCgroup => "create the agent's cgroup",
            Self::Placement => "place the agent's processes in its cgroup",
            Self::Controllers => "enable the cgroup controllers",
            Self::AgentMemoryLow => "set the agent's memory reservation",
            Self::WorkloadCgroup => "create the workload cgroup",
            Self::WorkloadMemoryMax => "set the workload's memory limit",
            Self::WorkloadPidsMax => "set the workload's process limit",
        })
    }
}

/// The cgroups that [`bootstrap`] prepared, and the processes that it moved into the agent's.
#[derive(Clone, Debug)]
pub struct Bootstrap {
    /// The agent's cgroup and the workload cgroup.
    layout: Layout,
    /// The handle of the workload cgroup itself.
    workload: ExecutionCgroup,
    /// The processes that the placement moved, in the order in which it moved them.
    moved: Vec<u32>,
}

impl Bootstrap {
    /// Returns the agent's cgroup and the workload cgroup.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Returns the handle of the workload cgroup itself, through which a caller that runs one
    /// execution at a time places, kills, and settles it, and below which another prepares the
    /// cgroup of each execution.
    pub fn workload(&self) -> &ExecutionCgroup {
        &self.workload
    }

    /// Returns the IDs of the processes that the bootstrap moved into the agent's cgroup, in the
    /// order in which it moved them.
    pub fn moved(&self) -> &[u32] {
        &self.moved
    }
}

/// Bootstraps the guest for a layered root: user namespaces, and the agent's and the workload's
/// cgroups of `layout`, which must be siblings. In order, it:
///
/// 1. sets `user.max_user_namespaces` to 0, so that no process creates a user namespace, even on
///    a kernel that supports them;
/// 2. mounts the cgroup v2 hierarchy, `nosuid,nodev,noexec`, at the cgroups' parent, unless the
///    parent is a cgroup already, which its `cgroup.controllers` shows;
/// 3. creates the agent's cgroup unless it exists;
/// 4. moves every process of the parent cgroup into the agent's cgroup, except kernel threads,
///    which stay: the caller, and every daemon that its prelude started. It repeats until no
///    such process is left, for at most 16 passes, so that one that a moved process starts
///    meanwhile moves too, and fails with `EBUSY` if one is still left;
/// 5. enables the `pids` controller, and the `memory` controller when a memory value needs it,
///    in the parent's `cgroup.subtree_control`, in one write;
/// 6. writes the agent's `memory.low`;
/// 7. creates the workload cgroup unless it exists;
/// 8. and writes its `memory.max` and `pids.max`.
///
/// Each value is written only when `resources` holds one. A failure names its step, and leaves
/// the earlier steps' changes in place. The bootstrap collects no status, and starts and stops
/// no process.
pub fn bootstrap(layout: &Layout, resources: &Resources) -> Result<Bootstrap, Error> {
    bootstrap_with(&mut SystemKernel, &Paths::default(), layout, resources)
}

/// Implements [`bootstrap`] with `kernel`, and with procfs at `paths.proc`.
pub(super) fn bootstrap_with(
    kernel: &mut dyn Kernel,
    paths: &Paths,
    layout: &Layout,
    resources: &Resources,
) -> Result<Bootstrap, Error> {
    let failed = |step| move |error| Error::Bootstrap { step, error };
    let parent = match (layout.agent().parent(), layout.workload().parent()) {
        (Some(agent), Some(workload)) if agent == workload => agent,
        _ => return Err(failed(BootstrapStep::Layout)(Errno::EINVAL.into())),
    };
    write(kernel, &paths.proc.join(USER_NAMESPACES), b"0")
        .map_err(failed(BootstrapStep::UserNamespaces))?;
    mount_hierarchy(kernel, parent).map_err(failed(BootstrapStep::Hierarchy))?;
    create_cgroup(layout.agent()).map_err(failed(BootstrapStep::AgentCgroup))?;
    let moved =
        place(kernel, paths, parent, layout.agent()).map_err(failed(BootstrapStep::Placement))?;
    let controllers: &[u8] = if resources.need_memory() {
        b"+pids +memory"
    } else {
        b"+pids"
    };
    write(kernel, &parent.join("cgroup.subtree_control"), controllers)
        .map_err(failed(BootstrapStep::Controllers))?;
    if let Some(low) = resources.agent_memory_low {
        write(
            kernel,
            &layout.agent().join("memory.low"),
            low.to_string().as_bytes(),
        )
        .map_err(failed(BootstrapStep::AgentMemoryLow))?;
    }
    create_cgroup(layout.workload()).map_err(failed(BootstrapStep::WorkloadCgroup))?;
    for (value, file, step) in [
        (
            resources.workload_memory_max,
            "memory.max",
            BootstrapStep::WorkloadMemoryMax,
        ),
        (
            resources.workload_pids_max,
            "pids.max",
            BootstrapStep::WorkloadPidsMax,
        ),
    ] {
        if let Some(value) = value {
            write(
                kernel,
                &layout.workload().join(file),
                value.to_string().as_bytes(),
            )
            .map_err(failed(step))?;
        }
    }
    let workload =
        ExecutionCgroup::open(layout, None).map_err(failed(BootstrapStep::WorkloadCgroup))?;
    Ok(Bootstrap {
        layout: layout.clone(),
        workload,
        moved,
    })
}

/// Writes `value` to the control file `path` through `kernel`.
fn write(kernel: &mut dyn Kernel, path: &Path, value: &[u8]) -> io::Result<()> {
    let path = sys::path_c_string(path)?;
    Ok(kernel.write(&path, value)?)
}

/// Mounts the cgroup v2 hierarchy at `parent`, which must exist, unless `parent` is a cgroup.
fn mount_hierarchy(kernel: &mut dyn Kernel, parent: &Path) -> io::Result<()> {
    match fs::symlink_metadata(parent.join("cgroup.controllers")) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if !fs::metadata(parent)?.is_dir() {
        return Err(Errno::ENOTDIR.into());
    }
    let target = sys::path_c_string(parent)?;
    Ok(kernel.mount(
        Some(c"cgroup2"),
        &target,
        Some(c"cgroup2"),
        MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC,
        None,
    )?)
}

/// Creates the cgroup `path` unless it exists. A file in its place is `ENOTDIR`.
fn create_cgroup(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o755).create(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path)?.is_dir() {
                Ok(())
            } else {
                Err(Errno::ENOTDIR.into())
            }
        }
        result => result,
    }
}

/// Moves every process of the cgroup `parent` into the cgroup `agent`, except kernel threads, in
/// passes until a pass finds none to move, and returns the IDs that it moved.
fn place(
    kernel: &mut dyn Kernel,
    paths: &Paths,
    parent: &Path,
    agent: &Path,
) -> io::Result<Vec<u32>> {
    let members = parent.join("cgroup.procs");
    let destination = sys::path_c_string(&agent.join("cgroup.procs"))?;
    let mut moved = Vec::new();
    for _ in 0..PLACEMENT_PASSES {
        let mut found = false;
        for process in processes(&fs::read(&members)?)? {
            match fs::read(paths.proc.join(process.to_string()).join("stat")) {
                Ok(stat) if is_kernel_thread(&stat).ok_or(Errno::EPROTO)? => continue,
                Ok(_) => {}
                // The process has ended.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) if error.raw_os_error() == Some(Errno::ESRCH as i32) => continue,
                Err(error) => return Err(error),
            }
            found = true;
            match kernel.write(&destination, process.to_string().as_bytes()) {
                Ok(()) => moved.push(process),
                Err(Errno::ESRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !found {
            return Ok(moved);
        }
    }
    Err(Errno::EBUSY.into())
}

/// Parses a cgroup's `cgroup.procs`: one decimal process ID per line.
fn processes(members: &[u8]) -> io::Result<Vec<u32>> {
    let Some(members) = members.strip_suffix(b"\n") else {
        return if members.is_empty() {
            Ok(Vec::new())
        } else {
            Err(Errno::EPROTO.into())
        };
    };
    members
        .split(|&byte| byte == b'\n')
        .map(|line| {
            parse_decimal(line)
                .and_then(|process| u32::try_from(process).ok())
                .filter(|&process| process != 0)
                .ok_or_else(|| Errno::EPROTO.into())
        })
        .collect()
}

/// Returns whether the `/proc/PID/stat` record `stat` is a kernel thread's, or `None` for a
/// malformed record. Its flags are the seventh field after the command, which is parenthesized
/// and may hold any character, a `)` and spaces included.
fn is_kernel_thread(stat: &[u8]) -> Option<bool> {
    let end = stat.iter().rposition(|&byte| byte == b')')?;
    let flags = stat[end + 1..]
        .split(|&byte| byte == b' ')
        .filter(|field| !field.is_empty())
        .nth(6)?;
    Some(parse_decimal(flags)? & KERNEL_THREAD != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_threads_are_known_by_their_flags() {
        let user = b"512 (sh) S 1 512 512 34816 512 4194560 147 0 0 0 0 0 0 0 20 0 1 0 72\n";
        let kernel = b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1\n";
        assert_eq!(is_kernel_thread(user), Some(false));
        assert_eq!(is_kernel_thread(kernel), Some(true));
        // A command with a parenthesis and spaces of its own.
        let tricky = b"77 (a) b (c)) S 1 77 77 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 9\n";
        assert_eq!(is_kernel_thread(tricky), Some(false));
        for malformed in [
            &b""[..],
            b"77 (sh S 1 77 77 0 -1 4194560",
            b"77 (sh) S 1 77 77 0 -1",
            b"77 (sh) S 1 77 77 0 -1 0x10 0",
        ] {
            assert_eq!(
                is_kernel_thread(malformed),
                None,
                "{}",
                malformed.escape_ascii()
            );
        }
    }

    #[test]
    fn membership_lists_are_decimal_lines() {
        assert_eq!(processes(b"").unwrap(), Vec::<u32>::new());
        assert_eq!(processes(b"1\n42\n4194304\n").unwrap(), [1, 42, 4_194_304]);
        for malformed in [
            &b"1"[..],
            b"\n",
            b"1\n\n",
            b"0\n",
            b"x\n",
            b"-1\n",
            b"4294967296\n",
        ] {
            assert_eq!(
                processes(malformed).unwrap_err().raw_os_error(),
                Some(Errno::EPROTO as i32),
                "{}",
                malformed.escape_ascii()
            );
        }
    }
}
