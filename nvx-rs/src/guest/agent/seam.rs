use std::ffi::{CStr, CString};
use std::io;
use std::path::{Path, PathBuf};

use super::launch::{self, SpawnRequest};

#[derive(Clone, Debug)]
pub(crate) struct Paths {
    pub(crate) cgroup_root: PathBuf,
    pub(crate) container_cgroup_procs: PathBuf,
    pub(crate) hostfs_dir: PathBuf,
    pub(crate) proc_cmdline: PathBuf,
    pub(crate) diagnostic_port: PathBuf,
    pub(crate) null_device: PathBuf,
    pub(crate) barrier: PathBuf,
    pub(crate) helper: PathBuf,
    pub(crate) launcher: PathBuf,
    pub(crate) exit: PathBuf,
    pub(crate) setpriv: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            cgroup_root: "/sys/fs/cgroup".into(),
            container_cgroup_procs: "/sys/fs/cgroup/container/cgroup.procs".into(),
            hostfs_dir: "/run/nvx/hostfs".into(),
            proc_cmdline: "/proc/cmdline".into(),
            diagnostic_port: "/dev/port".into(),
            null_device: "/dev/null".into(),
            barrier: "/run/nvx/managed-container-start".into(),
            helper: "/sbin/nvx-managed-agent".into(),
            launcher: "/sbin/nvx-container-launch".into(),
            exit: "/sbin/nvx-exit".into(),
            setpriv: "/bin/setpriv".into(),
        }
    }
}

pub(crate) trait System {
    fn paths(&self) -> &Paths;

    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: libc::c_ulong,
    ) -> io::Result<()>;

    fn chown(&mut self, path: &CStr, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()>;
    fn chmod(&mut self, path: &CStr, mode: libc::mode_t) -> io::Result<()>;
    fn configure_tty(&mut self, fd: libc::c_int) -> io::Result<()>;
    fn drain_tty(&mut self, fd: libc::c_int) -> io::Result<()>;
    fn write_diagnostic(&mut self, message: &[u8]) -> io::Result<()>;
    fn write_barrier(&mut self, fd: libc::c_int, message: &[u8]) -> io::Result<()>;
    fn validate_environment(&mut self, name: &CStr, value: &CStr) -> io::Result<()>;
    fn set_env(&mut self, name: &CStr, value: &CStr) -> io::Result<()>;
    fn unset_env(&mut self, name: &CStr) -> io::Result<()>;
    fn clear_env(&mut self) -> io::Result<()>;
    fn exec(&mut self, path: &CStr, arguments: &[*const libc::c_char]) -> io::Result<()>;
    fn spawn(&mut self, request: SpawnRequest<'_>) -> io::Result<libc::pid_t>;
}

pub(crate) struct RealSystem {
    paths: Paths,
}

impl RealSystem {
    pub(crate) fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl System for RealSystem {
    fn paths(&self) -> &Paths {
        &self.paths
    }

    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: libc::c_ulong,
    ) -> io::Result<()> {
        // SAFETY: all non-null pointers name NUL-terminated strings, and no data option is used.
        let result = unsafe {
            libc::mount(
                source.map_or(std::ptr::null(), CStr::as_ptr),
                target.as_ptr(),
                filesystem.map_or(std::ptr::null(), CStr::as_ptr),
                flags,
                std::ptr::null(),
            )
        };
        cvt(result)
    }

    fn chown(&mut self, path: &CStr, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
        // SAFETY: `path` is NUL-terminated.
        cvt(unsafe { libc::chown(path.as_ptr(), uid, gid) })
    }

    fn chmod(&mut self, path: &CStr, mode: libc::mode_t) -> io::Result<()> {
        // SAFETY: `path` is NUL-terminated.
        cvt(unsafe { libc::chmod(path.as_ptr(), mode) })
    }

    fn configure_tty(&mut self, fd: libc::c_int) -> io::Result<()> {
        // SAFETY: termios calls accept an open terminal descriptor and initialized storage.
        unsafe {
            let mut settings: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut settings) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::cfmakeraw(&mut settings);
            settings.c_cflag |= libc::CLOCAL;
            cvt(libc::tcsetattr(fd, libc::TCSANOW, &settings))
        }
    }

    fn drain_tty(&mut self, fd: libc::c_int) -> io::Result<()> {
        // SAFETY: tcdrain accepts an open terminal descriptor.
        cvt(unsafe { libc::tcdrain(fd) })
    }

    fn write_diagnostic(&mut self, message: &[u8]) -> io::Result<()> {
        let path = path_c_string(&self.paths.diagnostic_port)?;
        // SAFETY: `path` is NUL-terminated and O_CREAT is absent.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut result = Ok(());
        for byte in message {
            // SAFETY: pwrite reads one byte and does not change the descriptor offset.
            if unsafe { libc::pwrite(fd, std::ptr::from_ref(byte).cast(), 1, 0xe9) } != 1 {
                result = Err(io::Error::last_os_error());
                break;
            }
        }
        // SAFETY: this function owns the descriptor.
        unsafe { libc::close(fd) };
        result
    }

    fn write_barrier(&mut self, fd: libc::c_int, message: &[u8]) -> io::Result<()> {
        super::diagnostics::write_all(fd, message)
    }

    fn validate_environment(&mut self, _name: &CStr, _value: &CStr) -> io::Result<()> {
        Ok(())
    }

    fn set_env(&mut self, name: &CStr, value: &CStr) -> io::Result<()> {
        // SAFETY: both strings are NUL-terminated.
        cvt(unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) })
    }

    fn unset_env(&mut self, name: &CStr) -> io::Result<()> {
        // SAFETY: `name` is NUL-terminated.
        cvt(unsafe { libc::unsetenv(name.as_ptr()) })
    }

    fn clear_env(&mut self) -> io::Result<()> {
        // SAFETY: clearenv takes no arguments and leaves a valid empty environment.
        cvt(unsafe { libc::clearenv() })
    }

    fn exec(&mut self, path: &CStr, arguments: &[*const libc::c_char]) -> io::Result<()> {
        // SAFETY: `arguments` is NUL-terminated and every preceding pointer names a CString
        // retained by the caller.
        unsafe { libc::execv(path.as_ptr(), arguments.as_ptr()) };
        Err(io::Error::last_os_error())
    }

    fn spawn(&mut self, request: SpawnRequest<'_>) -> io::Result<libc::pid_t> {
        launch::spawn(&self.paths, request)
    }
}

pub(crate) fn path_c_string(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
pub(crate) struct TestSystem {
    pub(crate) paths: Paths,
    pub(crate) mounts: Vec<(Option<Vec<u8>>, Vec<u8>, libc::c_ulong)>,
    pub(crate) fail_mount_call: Option<usize>,
    pub(crate) diagnostics: Vec<u8>,
    pub(crate) environment: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) unset: Vec<Vec<u8>>,
    pub(crate) clear_count: usize,
    pub(crate) fail_environment: Option<Vec<u8>>,
    pub(crate) execs: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    pub(crate) tty_configured: usize,
    pub(crate) tty_drained: usize,
    pub(crate) close_barrier_reader: Option<libc::c_int>,
    pub(crate) fail_barrier_write: Option<i32>,
}

#[cfg(test)]
impl TestSystem {
    pub(crate) fn new(paths: Paths) -> Self {
        Self {
            paths,
            mounts: Vec::new(),
            fail_mount_call: None,
            diagnostics: Vec::new(),
            environment: Vec::new(),
            unset: Vec::new(),
            clear_count: 0,
            fail_environment: None,
            execs: Vec::new(),
            tty_configured: 0,
            tty_drained: 0,
            close_barrier_reader: None,
            fail_barrier_write: None,
        }
    }
}

#[cfg(test)]
impl System for TestSystem {
    fn paths(&self) -> &Paths {
        &self.paths
    }

    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        _filesystem: Option<&CStr>,
        flags: libc::c_ulong,
    ) -> io::Result<()> {
        self.mounts.push((
            source.map(|source| source.to_bytes().to_vec()),
            target.to_bytes().to_vec(),
            flags,
        ));
        if self.fail_mount_call == Some(self.mounts.len()) {
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        } else {
            Ok(())
        }
    }

    fn chown(&mut self, _path: &CStr, _uid: libc::uid_t, _gid: libc::gid_t) -> io::Result<()> {
        Ok(())
    }

    fn chmod(&mut self, _path: &CStr, _mode: libc::mode_t) -> io::Result<()> {
        Ok(())
    }

    fn configure_tty(&mut self, _fd: libc::c_int) -> io::Result<()> {
        self.tty_configured += 1;
        Ok(())
    }

    fn drain_tty(&mut self, _fd: libc::c_int) -> io::Result<()> {
        self.tty_drained += 1;
        Ok(())
    }

    fn write_diagnostic(&mut self, message: &[u8]) -> io::Result<()> {
        self.diagnostics.extend_from_slice(message);
        Ok(())
    }

    fn write_barrier(&mut self, fd: libc::c_int, message: &[u8]) -> io::Result<()> {
        if let Some(reader) = self.close_barrier_reader.take() {
            // SAFETY: the test owns this descriptor and closes it once.
            unsafe { libc::close(reader) };
        }
        if let Some(status) = self.fail_barrier_write {
            return Err(io::Error::from_raw_os_error(status));
        }
        super::diagnostics::write_all(fd, message)
    }

    fn validate_environment(&mut self, name: &CStr, _value: &CStr) -> io::Result<()> {
        if self
            .fail_environment
            .as_deref()
            .is_some_and(|failure| failure == name.to_bytes())
        {
            Err(io::Error::from_raw_os_error(libc::ENOMEM))
        } else {
            Ok(())
        }
    }

    fn set_env(&mut self, name: &CStr, value: &CStr) -> io::Result<()> {
        if self
            .fail_environment
            .as_deref()
            .is_some_and(|failure| failure == name.to_bytes())
        {
            return Err(io::Error::from_raw_os_error(libc::ENOMEM));
        }
        self.environment
            .push((name.to_bytes().to_vec(), value.to_bytes().to_vec()));
        Ok(())
    }

    fn unset_env(&mut self, name: &CStr) -> io::Result<()> {
        self.unset.push(name.to_bytes().to_vec());
        Ok(())
    }

    fn clear_env(&mut self) -> io::Result<()> {
        self.clear_count += 1;
        Ok(())
    }

    fn exec(&mut self, path: &CStr, arguments: &[*const libc::c_char]) -> io::Result<()> {
        let mut decoded = Vec::new();
        for &argument in arguments {
            if argument.is_null() {
                break;
            }
            // SAFETY: test callers pass pointers to retained CStrings.
            decoded.push(unsafe { CStr::from_ptr(argument) }.to_bytes().to_vec());
        }
        self.execs.push((path.to_bytes().to_vec(), decoded));
        Ok(())
    }

    fn spawn(&mut self, _request: SpawnRequest<'_>) -> io::Result<libc::pid_t> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}
