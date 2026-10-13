use std::io;
use std::path::Path;
use std::time::Duration;

use super::diagnostics::{errno, write_all};
use super::seam::{System, path_c_string};

const SETTLE_ATTEMPTS: usize = 200;
const SETTLE_DELAY: Duration = Duration::from_millis(10);

pub(crate) fn prepare(system: &mut impl System) -> io::Result<()> {
    let root = system.paths().cgroup_root.clone();
    if std::fs::metadata(root.join("cgroup.procs")).is_err() {
        mkdir(&root, 0o755)?;
        let target = path_c_string(&root)?;
        system.mount(
            Some(c"cgroup2"),
            &target,
            Some(c"cgroup2"),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        )?;
    }
    let execution = root.join("nvx-exec");
    mkdir(&execution, 0o755)?;
    match std::fs::metadata(execution.join("pids.current")) {
        Ok(_) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            write_path(&root.join("cgroup.subtree_control"), b"+pids")
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn has_tasks(system: &impl System) -> io::Result<bool> {
    let path = system
        .paths()
        .cgroup_root
        .join("nvx-exec")
        .join("pids.current");
    let path = path_c_string(&path)?;
    // SAFETY: `path` is NUL-terminated and O_CREAT is absent.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = [0u8; 32];
    let mut length = 0;
    let result = loop {
        // SAFETY: the unused suffix is writable.
        let count = unsafe {
            libc::read(
                fd,
                buffer[length..].as_mut_ptr().cast(),
                buffer.len() - length,
            )
        };
        if count > 0 {
            length += count as usize;
            if length < buffer.len() {
                continue;
            }
            break Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        if count == 0 {
            break parse_count(&buffer[..length]);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            break Err(error);
        }
    };
    // SAFETY: this function owns the descriptor.
    let closed = unsafe { libc::close(fd) };
    match (result, closed) {
        (Ok(value), 0) => Ok(value),
        (Ok(_), _) => Err(io::Error::last_os_error()),
        (Err(error), _) => Err(error),
    }
}

fn parse_count(bytes: &[u8]) -> io::Result<bool> {
    if bytes.len() < 2
        || bytes.last() != Some(&b'\n')
        || (bytes.first() == Some(&b'0') && bytes.len() != 2)
        || !bytes[..bytes.len() - 1].iter().all(u8::is_ascii_digit)
    {
        return Err(io::Error::from_raw_os_error(libc::EPROTO));
    }
    Ok(bytes.first() != Some(&b'0'))
}

pub(crate) fn kill(system: &mut impl System) -> io::Result<()> {
    let path = system
        .paths()
        .cgroup_root
        .join("nvx-exec")
        .join("cgroup.kill");
    let result = write_path(&path, b"1");
    if let Err(error) = &result {
        let status = errno(error);
        super::diagnostics::error(system, "exec-cgroup-kill", status);
    }
    result
}

pub(crate) fn reap(child: libc::pid_t, child_exited: &mut bool, status: &mut i32) {
    loop {
        let mut observed = 0;
        // SAFETY: waitpid writes an integer status and WNOHANG does not block.
        let pid = unsafe { libc::waitpid(-1, &mut observed, libc::WNOHANG) };
        if pid < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if pid <= 0 {
            return;
        }
        if pid == child && !*child_exited {
            *child_exited = true;
            *status = observed;
        }
    }
}

pub(crate) fn verify_empty(system: &impl System) -> io::Result<bool> {
    let mut ignored = true;
    let mut status = 0;
    reap(0, &mut ignored, &mut status);
    has_tasks(system)
}

pub(crate) fn settle(system: &mut impl System) -> io::Result<()> {
    kill(system)?;
    for attempt in 0..=SETTLE_ATTEMPTS {
        if !verify_empty(system)? {
            return Ok(());
        }
        if attempt != SETTLE_ATTEMPTS {
            std::thread::sleep(SETTLE_DELAY);
        }
    }
    Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
}

pub(crate) fn terminate(system: &mut impl System, direct: bool, child: libc::pid_t) {
    // SAFETY: a negative PID addresses the workload's process group.
    unsafe { libc::kill(-child, libc::SIGKILL) };
    if direct {
        let _ = kill(system);
    }
}

pub(crate) fn write_container_pid(system: &impl System, child: libc::pid_t) -> io::Result<()> {
    let mut value = child.to_string().into_bytes();
    value.push(b'\n');
    write_path(&system.paths().container_cgroup_procs, &value)
}

fn mkdir(path: &Path, mode: libc::mode_t) -> io::Result<()> {
    let path = path_c_string(path)?;
    // SAFETY: `path` is NUL-terminated.
    let result = unsafe { libc::mkdir(path.as_ptr(), mode) };
    if result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn write_path(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let path = path_c_string(path)?;
    // SAFETY: `path` is NUL-terminated and O_CREAT is absent.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = write_all(fd, bytes);
    let status = result.as_ref().err().map(errno);
    // SAFETY: this function owns the descriptor.
    let closed = unsafe { libc::close(fd) };
    if let Some(status) = status {
        return Err(io::Error::from_raw_os_error(status));
    }
    if closed != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn setup() -> (tempfile::TempDir, TestSystem) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cgroup");
        let execution = root.join("nvx-exec");
        std::fs::create_dir_all(&execution).unwrap();
        std::fs::write(root.join("cgroup.procs"), b"").unwrap();
        std::fs::write(root.join("cgroup.subtree_control"), b"").unwrap();
        std::fs::write(execution.join("pids.current"), b"0\n").unwrap();
        std::fs::write(execution.join("cgroup.kill"), b"").unwrap();
        std::fs::write(execution.join("cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: root,
            ..Paths::default()
        };
        (temporary, TestSystem::new(paths))
    }

    #[test]
    fn task_count_requires_a_canonical_decimal() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, system) = setup();
        let tasks = system.paths.cgroup_root.join("nvx-exec/pids.current");
        for (contents, expected) in [
            (b"0\n".as_slice(), false),
            (b"1\n", true),
            (b"10\n", true),
            (b"4194304\n", true),
        ] {
            std::fs::write(&tasks, contents).unwrap();
            assert_eq!(has_tasks(&system).unwrap(), expected, "{contents:?}");
        }
        for contents in [
            b"".as_slice(),
            b"\n",
            b"0",
            b"00\n",
            b"01\n",
            b"-1\n",
            b"+1\n",
            b" 1\n",
            b"1 \n",
            b"0\n0\n",
            b"1\0\n",
            b"max\n",
        ] {
            std::fs::write(&tasks, contents).unwrap();
            assert_eq!(
                has_tasks(&system).unwrap_err().raw_os_error(),
                Some(libc::EPROTO),
                "{contents:?}"
            );
        }
        std::fs::write(&tasks, [b'1'; 40]).unwrap();
        assert_eq!(
            has_tasks(&system).unwrap_err().raw_os_error(),
            Some(libc::EOVERFLOW)
        );
    }

    #[test]
    fn missing_and_unreadable_task_counts_are_errors() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, system) = setup();
        let tasks = system.paths.cgroup_root.join("nvx-exec/pids.current");
        std::fs::remove_file(&tasks).unwrap();
        assert_eq!(
            has_tasks(&system).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        std::fs::create_dir(&tasks).unwrap();
        assert!(has_tasks(&system).is_err());
    }

    #[test]
    fn preparation_enables_the_pids_controller_once() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = setup();
        let root = system.paths.cgroup_root.clone();
        prepare(&mut system).unwrap();
        assert_eq!(
            std::fs::read(root.join("cgroup.subtree_control")).unwrap(),
            b""
        );
        std::fs::remove_file(root.join("nvx-exec/pids.current")).unwrap();
        prepare(&mut system).unwrap();
        assert_eq!(
            std::fs::read(root.join("cgroup.subtree_control")).unwrap(),
            b"+pids"
        );
        std::fs::remove_file(root.join("cgroup.subtree_control")).unwrap();
        assert_eq!(
            prepare(&mut system).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn settlement_verifies_emptiness_and_propagates_failures() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = setup();
        let execution = system.paths.cgroup_root.join("nvx-exec");
        settle(&mut system).unwrap();
        assert_eq!(std::fs::read(execution.join("cgroup.kill")).unwrap(), b"1");

        std::fs::remove_file(execution.join("cgroup.kill")).unwrap();
        assert_eq!(
            settle(&mut system).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        std::fs::write(execution.join("cgroup.kill"), b"").unwrap();
        std::fs::write(execution.join("pids.current"), b"bad\n").unwrap();
        assert_eq!(
            settle(&mut system).unwrap_err().raw_os_error(),
            Some(libc::EPROTO)
        );
    }

    #[test]
    fn verification_reaps_orphaned_children() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, system) = setup();
        // SAFETY: the child performs only _exit; the parent owns and reaps it.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: exits the fork child without running Rust destructors.
            unsafe { libc::_exit(0) }
        }
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: waits until the child is a reapable zombie without consuming it.
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    child as libc::id_t,
                    &mut information,
                    libc::WEXITED | libc::WNOWAIT,
                )
            },
            0
        );
        assert!(!verify_empty(&system).unwrap());
        let mut status = 0;
        // SAFETY: the preceding verification already reaped the child.
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn unreaped_tasks_at_deadline_are_not_settled() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = setup();
        std::fs::write(
            system.paths.cgroup_root.join("nvx-exec/pids.current"),
            b"1\n",
        )
        .unwrap();
        assert_eq!(
            settle(&mut system).unwrap_err().raw_os_error(),
            Some(libc::ETIMEDOUT)
        );
    }
}
