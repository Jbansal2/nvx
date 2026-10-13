//! Binds the privileged UDP source port and runs the live scan/send loop.

use std::ffi::CStr;
use std::io::Write;
use std::mem::size_of;
use std::path::Path;

use super::collect::{self, Collector, DiagnosticInput};
use super::{
    ANNOUNCEMENT_PORT, FIRST_SOURCE_PORT, LAST_SOURCE_PORT, REFRESH_INTERVAL_MS, SCAN_INTERVAL_MS,
};
use crate::guest::sys::Errno;

unsafe extern "C" {
    fn inet_pton(
        address_family: libc::c_int,
        source: *const libc::c_char,
        destination: *mut libc::c_void,
    ) -> libc::c_int;
}

trait System {
    fn ignore_signals(&mut self);
    fn ipv6_dual_stack(&mut self) -> bool;
    fn socket(&mut self) -> Result<libc::c_int, Errno>;
    fn bind(&mut self, descriptor: libc::c_int, port: u16) -> Result<(), Errno>;
    fn now_ms(&mut self) -> u64;
    fn collect(&mut self, own_port: u16, now: u64, ipv6_dual_stack: bool) -> Vec<u8>;
    fn send(
        &mut self,
        descriptor: libc::c_int,
        destination: &libc::sockaddr_in,
        payload: &[u8],
    ) -> bool;
    fn sleep_ms(&mut self, milliseconds: u64);
}

struct RealSystem {
    collector: Collector,
}

impl RealSystem {
    fn new() -> Self {
        Self {
            collector: Collector::new(),
        }
    }
}

impl System for RealSystem {
    fn ignore_signals(&mut self) {
        // SAFETY: ignored dispositions install no handler.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
    }

    fn ipv6_dual_stack(&mut self) -> bool {
        collect::read_bindv6only(Path::new("/proc"), true)
    }

    fn socket(&mut self) -> Result<libc::c_int, Errno> {
        // SAFETY: socket is called with an IPv4 datagram family and no pointers.
        let descriptor =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if descriptor < 0 {
            Err(Errno::last())
        } else {
            Ok(descriptor)
        }
    }

    fn bind(&mut self, descriptor: libc::c_int, port: u16) -> Result<(), Errno> {
        // SAFETY: all-zero is a valid initial sockaddr_in.
        let mut source: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        source.sin_family = libc::AF_INET as libc::sa_family_t;
        source.sin_port = port.to_be();
        source.sin_addr.s_addr = libc::INADDR_ANY.to_be();
        // SAFETY: source points to an initialized IPv4 socket address of the supplied size.
        if unsafe {
            libc::bind(
                descriptor,
                std::ptr::addr_of!(source).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(Errno::last())
        }
    }

    fn now_ms(&mut self) -> u64 {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes one initialized timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
        (now.tv_sec as u64)
            .wrapping_mul(1_000)
            .wrapping_add((now.tv_nsec as u64) / 1_000_000)
    }

    fn collect(&mut self, own_port: u16, now: u64, ipv6_dual_stack: bool) -> Vec<u8> {
        self.collector.collect_files(
            Path::new("/proc"),
            DiagnosticInput::Live,
            own_port,
            now,
            ipv6_dual_stack,
        )
    }

    fn send(
        &mut self,
        descriptor: libc::c_int,
        destination: &libc::sockaddr_in,
        payload: &[u8],
    ) -> bool {
        // SAFETY: both pointers name initialized buffers for their supplied lengths.
        (unsafe {
            libc::sendto(
                descriptor,
                payload.as_ptr().cast(),
                payload.len(),
                0,
                std::ptr::from_ref(destination).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }) == payload.len() as isize
    }

    fn sleep_ms(&mut self, milliseconds: u64) {
        let mut delay = libc::timespec {
            tv_sec: (milliseconds / 1_000) as _,
            tv_nsec: ((milliseconds % 1_000) * 1_000_000) as libc::c_long,
        };
        loop {
            let mut remaining = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: nanosleep reads `delay` and writes `remaining`.
            if unsafe { libc::nanosleep(&delay, &mut remaining) } == 0
                || Errno::last().0 != libc::EINTR
            {
                break;
            }
            delay = remaining;
        }
    }
}

pub(super) fn run(gateway: &CStr, err: &mut dyn Write) -> u8 {
    let Some(destination) = destination(gateway) else {
        return super::usage(err);
    };
    run_with(&mut RealSystem::new(), &destination, err, None)
}

fn destination(gateway: &CStr) -> Option<libc::sockaddr_in> {
    // SAFETY: all-zero is a valid initial sockaddr_in.
    let mut destination: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    destination.sin_family = libc::AF_INET as libc::sa_family_t;
    destination.sin_port = ANNOUNCEMENT_PORT.to_be();
    // SAFETY: the gateway is NUL-terminated and inet_pton writes one in_addr.
    (unsafe {
        inet_pton(
            libc::AF_INET,
            gateway.as_ptr(),
            std::ptr::addr_of_mut!(destination.sin_addr).cast(),
        )
    } == 1)
        .then_some(destination)
}

fn run_with(
    system: &mut impl System,
    destination: &libc::sockaddr_in,
    err: &mut dyn Write,
    scan_limit: Option<usize>,
) -> u8 {
    system.ignore_signals();
    let ipv6_dual_stack = system.ipv6_dual_stack();
    let socket = match system.socket() {
        Ok(socket) => socket,
        Err(errno) => {
            report_errno(err, b"nvx-ingress: socket: ", errno);
            return 1;
        }
    };

    let mut own_port = 0;
    for port in (LAST_SOURCE_PORT..=FIRST_SOURCE_PORT).rev() {
        match system.bind(socket, port) {
            Ok(()) => {
                own_port = port;
                break;
            }
            Err(Errno(libc::EADDRINUSE)) => {}
            Err(errno) => {
                report_errno(err, b"nvx-ingress: bind privileged port: ", errno);
                return 1;
            }
        }
    }
    if own_port == 0 {
        super::super::sys::report(err, &[b"nvx-ingress: no privileged source port is free\n"]);
        return 1;
    }

    let mut last_payload = Vec::new();
    let mut last_sent = 0_u64;
    let mut scans = 0;
    loop {
        let now = system.now_ms();
        let payload = system.collect(own_port, now, ipv6_dual_stack);
        if (payload != last_payload || now.wrapping_sub(last_sent) >= REFRESH_INTERVAL_MS)
            && system.send(socket, destination, &payload)
        {
            last_payload = payload;
            last_sent = now;
        }
        system.sleep_ms(SCAN_INTERVAL_MS);
        scans += 1;
        if scan_limit.is_some_and(|limit| scans >= limit) {
            return 0;
        }
    }
}

fn report_errno(err: &mut dyn Write, prefix: &[u8], errno: Errno) {
    let text = errno.text();
    super::super::sys::report(err, &[prefix, &text, b"\n"]);
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct FakeSystem {
        ignored_signals: bool,
        ipv6_dual_stack: bool,
        socket_error: Option<Errno>,
        bind_results: VecDeque<Result<(), Errno>>,
        default_bind: Result<(), Errno>,
        bound_ports: Vec<u16>,
        times: VecDeque<u64>,
        payloads: VecDeque<Vec<u8>>,
        collections: Vec<(u16, u64, bool)>,
        send_results: VecDeque<bool>,
        sends: Vec<Vec<u8>>,
        sleeps: Vec<u64>,
    }

    impl FakeSystem {
        fn one_scan() -> Self {
            Self {
                ignored_signals: false,
                ipv6_dual_stack: true,
                socket_error: None,
                bind_results: VecDeque::new(),
                default_bind: Ok(()),
                bound_ports: Vec::new(),
                times: VecDeque::from([100]),
                payloads: VecDeque::from([b"packet".to_vec()]),
                collections: Vec::new(),
                send_results: VecDeque::new(),
                sends: Vec::new(),
                sleeps: Vec::new(),
            }
        }
    }

    impl System for FakeSystem {
        fn ignore_signals(&mut self) {
            self.ignored_signals = true;
        }

        fn ipv6_dual_stack(&mut self) -> bool {
            self.ipv6_dual_stack
        }

        fn socket(&mut self) -> Result<libc::c_int, Errno> {
            self.socket_error.map_or(Ok(7), Err)
        }

        fn bind(&mut self, _: libc::c_int, port: u16) -> Result<(), Errno> {
            self.bound_ports.push(port);
            self.bind_results.pop_front().unwrap_or(self.default_bind)
        }

        fn now_ms(&mut self) -> u64 {
            self.times.pop_front().expect("a time for every test scan")
        }

        fn collect(&mut self, own_port: u16, now: u64, ipv6_dual_stack: bool) -> Vec<u8> {
            self.collections.push((own_port, now, ipv6_dual_stack));
            self.payloads
                .pop_front()
                .expect("a payload for every test scan")
        }

        fn send(&mut self, _: libc::c_int, _: &libc::sockaddr_in, payload: &[u8]) -> bool {
            self.sends.push(payload.to_vec());
            self.send_results.pop_front().unwrap_or(true)
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            self.sleeps.push(milliseconds);
        }
    }

    fn loopback_destination() -> libc::sockaddr_in {
        destination(c"127.0.0.1").unwrap()
    }

    #[test]
    fn sockaddr_and_timing_layouts_match_linux() {
        let destination = loopback_destination();
        assert_eq!(size_of::<libc::sockaddr_in>(), 16);
        assert_eq!(destination.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(u16::from_be(destination.sin_port), ANNOUNCEMENT_PORT);
        assert_eq!(SCAN_INTERVAL_MS, 100);
        assert_eq!(REFRESH_INTERVAL_MS, 2_000);
        assert!(super::destination(c"127.0.0.01").is_none());
    }

    #[test]
    fn privileged_bind_retries_eaddrinuse_and_uses_the_first_free_port() {
        let mut system = FakeSystem::one_scan();
        system.bind_results = VecDeque::from([
            Err(Errno(libc::EADDRINUSE)),
            Err(Errno(libc::EADDRINUSE)),
            Ok(()),
        ]);
        let mut err = Vec::new();
        assert_eq!(
            run_with(&mut system, &loopback_destination(), &mut err, Some(1)),
            0
        );
        assert!(system.ignored_signals);
        assert_eq!(system.bound_ports, [1023, 1022, 1021]);
        assert_eq!(system.collections, [(1021, 100, true)]);
        assert_eq!(system.sends, [b"packet".to_vec()]);
        assert_eq!(system.sleeps, [SCAN_INTERVAL_MS]);
        assert!(err.is_empty());
    }

    #[test]
    fn socket_and_non_address_in_use_bind_failures_are_reported() {
        for (socket_error, bind_error, prefix) in [
            (
                Some(Errno(libc::EMFILE)),
                None,
                b"nvx-ingress: socket: ".as_slice(),
            ),
            (
                None,
                Some(Errno(libc::EACCES)),
                b"nvx-ingress: bind privileged port: ".as_slice(),
            ),
        ] {
            let mut system = FakeSystem::one_scan();
            system.socket_error = socket_error;
            if let Some(error) = bind_error {
                system.bind_results.push_back(Err(error));
            }
            let mut err = Vec::new();
            assert_eq!(
                run_with(&mut system, &loopback_destination(), &mut err, Some(1)),
                1
            );
            let errno = socket_error.or(bind_error).unwrap();
            let mut expected = prefix.to_vec();
            expected.extend(errno.text());
            expected.push(b'\n');
            assert_eq!(err, expected);
            assert!(system.sends.is_empty());
        }
    }

    #[test]
    fn exhausting_the_privileged_range_reports_no_free_port() {
        let mut system = FakeSystem::one_scan();
        system.default_bind = Err(Errno(libc::EADDRINUSE));
        let mut err = Vec::new();
        assert_eq!(
            run_with(&mut system, &loopback_destination(), &mut err, Some(1)),
            1
        );
        assert_eq!(system.bound_ports.len(), 512);
        assert_eq!(
            (system.bound_ports.first(), system.bound_ports.last()),
            (Some(&FIRST_SOURCE_PORT), Some(&LAST_SOURCE_PORT))
        );
        assert_eq!(err, b"nvx-ingress: no privileged source port is free\n");
    }

    #[test]
    fn changed_packets_refreshes_and_failed_sends_control_sender_state() {
        let mut system = FakeSystem::one_scan();
        system.times = VecDeque::from([100, 200, 2_100, 2_200, 2_300]);
        system.payloads = VecDeque::from([
            b"A".to_vec(),
            b"A".to_vec(),
            b"A".to_vec(),
            b"A".to_vec(),
            b"B".to_vec(),
        ]);
        system.send_results = VecDeque::from([false, true, true, true]);
        let mut err = Vec::new();
        assert_eq!(
            run_with(&mut system, &loopback_destination(), &mut err, Some(5)),
            0
        );
        assert_eq!(
            system.sends,
            [b"A".to_vec(), b"A".to_vec(), b"A".to_vec(), b"B".to_vec()]
        );
        assert_eq!(system.sleeps, [SCAN_INTERVAL_MS; 5]);
        assert!(err.is_empty());
    }
}
