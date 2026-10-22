//! The worker's executions, as the worker's module documentation describes them: the table that
//! reaches each one by its ID, the generations that the host started, their admission, the
//! refusal of a start, the loop's steps of every execution, and the collection of the statuses of
//! the programs that the worker forgot.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags};
use nix::sys::wait::{self, WaitPidFlag, WaitStatus};
use nvx::exec::{Key, LaunchFailure, Runner, Settlement, Stream, Violation, runner};
use nvx::guest::exec::binding::{Binding, Event};
use nvx::guest::exec::{Execution, Options, Pipes, Source};
use nvx::guest::spawn::Command;

use super::connection::Connection;
use super::{MAX_EXECUTION_MEMORY, MAX_EXECUTIONS, MAX_HISTORY};
use crate::exec::{GuestMessage, HostMessage, MAX_CHUNK, Start, name};
use crate::guest::ServeError;

/// The device that a program without the host's input reads.
const NULL_DEVICE: &str = "/dev/null";

/// The interval at which the worker checks whether the programs that it forgot ended.
const REAP_INTERVAL: Duration = Duration::from_millis(10);

/// The longest that the worker waits for the programs of the executions that it drops at once.
const REAP_WAIT: Duration = Duration::from_secs(1);

/// The worker's executions.
pub(super) struct Executions {
    /// The executions that the host reaches, by ID.
    attached: BTreeMap<u64, Binding>,
    /// The executions that the host abandoned, which run until they end.
    detached: Vec<Binding>,
    /// The process IDs of the programs that the worker forgot before it collected their
    /// statuses, which it collects once they ended.
    reaping: Vec<u32>,
    /// When the worker last checked whether those programs ended.
    reaped: Option<Instant>,
    /// When the worker stops waiting for the programs once it dropped every execution: a while
    /// after it first did.
    cleared: Option<Instant>,
    /// The latest generation that the host started of each ID of `history`.
    generations: BTreeMap<u64, u64>,
    /// The IDs whose latest generation the worker remembers, in the order in which it heard of
    /// them first.
    history: VecDeque<u64>,
    /// The buffer into which each read of an output stream goes: a chunk at most.
    buffer: Vec<u8>,
}

impl Executions {
    /// Returns no executions.
    pub(super) fn new() -> Self {
        Self {
            attached: BTreeMap::new(),
            detached: Vec::new(),
            reaping: Vec::new(),
            reaped: None,
            cleared: None,
            generations: BTreeMap::new(),
            history: VecDeque::new(),
            buffer: vec![0; MAX_CHUNK as usize],
        }
    }

    /// Hands `message` from the host to its execution at `now`, and queues on `connection` the
    /// terminal record of a start that the worker refuses.
    pub(super) fn deliver<S: Read + Write + AsFd>(
        &mut self,
        now: Instant,
        message: HostMessage<'_>,
        connection: &mut Connection<S>,
    ) -> Result<(), ServeError> {
        let key = message.key();
        if let HostMessage::Start(start) = message {
            return self.start(now, start, connection);
        }
        // A message of an execution that the worker no longer runs is late.
        let Some(binding) = self.attached.get_mut(&key.id()) else {
            return Ok(());
        };
        let applied = match message {
            HostMessage::Input(key, bytes) => binding.input(key, bytes),
            HostMessage::InputEnd(key) => binding.end_input(key),
            HostMessage::Cancel(key, cause) => binding.cancel(now, key, cause),
            HostMessage::Credit(key, pool, units) => binding.credit(key, pool, units),
            HostMessage::Start(_) => unreachable!("a start is handled above"),
        };
        applied
            .map(|_receipt| ())
            .map_err(|violation| refused(key, violation))
    }

    /// Takes every step that the executions can take at `now`, queues their messages for the
    /// host on `connection`, forgets each execution once it returned its terminal outcome, and
    /// collects the statuses of the programs that it forgot, of those that ended. While the
    /// connection is backlogged, the executions that the host reaches take no output from their
    /// programs, and return only their other messages.
    pub(super) fn run<S: Read + Write + AsFd>(
        &mut self,
        now: Instant,
        connection: &mut Connection<S>,
    ) -> Result<(), ServeError> {
        let Self {
            attached,
            detached,
            reaping,
            buffer,
            ..
        } = self;
        for binding in attached.values_mut() {
            let key = binding.runner().key();
            loop {
                // Once records back up on the stream, an empty buffer lets the execution read no
                // output, and return none.
                let length = if connection.is_backlogged() {
                    0
                } else {
                    buffer.len()
                };
                let lent = &mut buffer[..length];
                let Some(event) = binding.next(now, lent) else {
                    break;
                };
                match event {
                    Event::Message(message) => {
                        if let Some(message) = GuestMessage::from_runner(key, message, lent) {
                            connection.send(&message.encode())?;
                        }
                    }
                    event => report(key, &event),
                }
            }
        }
        attached.retain(|_, binding| running(binding, reaping));
        for binding in detached.iter_mut() {
            let key = binding.runner().key();
            while let Some(event) = binding.next(now, buffer) {
                // A detached runner returns only its terminal outcome, which no host takes.
                if !matches!(event, Event::Message(_)) {
                    report(key, &event);
                }
            }
        }
        detached.retain(|binding| running(binding, reaping));
        self.reap(now);
        Ok(())
    }

    /// Abandons every execution at `now`, because the session was reset.
    pub(super) fn reset(&mut self, now: Instant) {
        for (_, mut binding) in std::mem::take(&mut self.attached) {
            binding.reset(now);
            self.detached.push(binding);
        }
    }

    /// Drops every execution, which ends its program and the program's process group, and waits
    /// for the programs to end, so that the worker collects their statuses, at most [`REAP_WAIT`]
    /// after it first dropped every execution: a later call, as once the executions drop after a
    /// stop, waits no longer.
    pub(super) fn clear(&mut self) {
        let Self {
            attached,
            detached,
            reaping,
            ..
        } = self;
        for binding in std::mem::take(attached)
            .into_values()
            .chain(detached.drain(..))
        {
            forget(&binding, reaping);
        }
        let deadline = *self
            .cleared
            .get_or_insert_with(|| Instant::now() + REAP_WAIT);
        loop {
            let now = Instant::now();
            self.reap(now);
            if self.reaping.is_empty() || now >= deadline {
                return;
            }
            thread::sleep(REAP_INTERVAL);
        }
    }

    /// Returns when an execution must take a step even if none of its descriptors polls ready,
    /// or when the worker checks next whether the programs that it forgot ended.
    pub(super) fn deadline(&self) -> Option<Instant> {
        let reaping = self
            .reaped
            .filter(|_| !self.reaping.is_empty())
            .map(|reaped| reaped + REAP_INTERVAL);
        self.bindings()
            .filter_map(Binding::deadline)
            .chain(reaping)
            .min()
    }

    /// Appends the executions' descriptors to `descriptors`, each with the readiness that it
    /// waits for, but those of the output of the executions that the host reaches while the
    /// connection is `backlogged`, as they take no output then.
    pub(super) fn poll_descriptors<'a>(
        &'a self,
        descriptors: &mut Vec<PollFd<'a>>,
        backlogged: bool,
    ) {
        let attached = self.attached.values().map(|binding| (binding, backlogged));
        let detached = self.detached.iter().map(|binding| (binding, false));
        for (binding, backlogged) in attached.chain(detached) {
            for (source, descriptor) in binding.descriptors() {
                if !(backlogged && matches!(source, Source::Output(_))) {
                    descriptors.push(PollFd::new(descriptor, PollFlags::POLLIN));
                }
            }
            if let Some(descriptor) = binding.input_writer() {
                descriptors.push(PollFd::new(descriptor, PollFlags::POLLOUT));
            }
        }
    }

    /// Returns every execution.
    fn bindings(&self) -> impl Iterator<Item = &Binding> {
        self.attached.values().chain(&self.detached)
    }

    /// Collects at `now` the statuses of the programs that the worker forgot, of those that
    /// ended.
    fn reap(&mut self, now: Instant) {
        self.reaping.retain(|&id| {
            // `ECHILD` tells that no status is left to collect.
            matches!(
                wait::waitpid(super::pid(id), Some(WaitPidFlag::WNOHANG)),
                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR)
            )
        });
        self.reaped = Some(now);
    }

    /// Starts the execution of `start` at `now`, or refuses it with a terminal record that it
    /// queues on `connection`. A start of an earlier generation than the latest that the host
    /// started of its ID is stale, and one of the same generation fails.
    fn start<S: Read + Write + AsFd>(
        &mut self,
        now: Instant,
        start: Start,
        connection: &mut Connection<S>,
    ) -> Result<(), ServeError> {
        let key = start.key;
        // The running execution of the ID, if any, holds the latest generation too, in case the
        // worker forgot the ID's generations meanwhile.
        let running = self
            .attached
            .get(&key.id())
            .map(|binding| binding.runner().key().generation());
        if let Some(latest) = self.generations.get(&key.id()).copied().max(running) {
            if key.generation() < latest {
                return Ok(());
            }
            if key.generation() == latest {
                return Err(ServeError::Execution(format!(
                    "execution {} starts twice",
                    name(key)
                )));
            }
        }
        self.remember(key);
        if let Some(mut abandoned) = self.attached.remove(&key.id()) {
            abandoned.dropped(now);
            self.detached.push(abandoned);
        }
        let runner = Runner::new(key, start.limits, start.timers, now);
        let executions = self.attached.len() + self.detached.len() + self.reaping.len();
        let admitted = if executions >= MAX_EXECUTIONS {
            Err(Errno::EAGAIN as i32)
        } else if runner.memory_bound() > MAX_EXECUTION_MEMORY {
            Err(Errno::ENOMEM as i32)
        } else {
            spawn(&start).map_err(|error| error.raw_os_error().unwrap_or(0))
        };
        match admitted {
            Ok(execution) => {
                self.attached
                    .insert(key.id(), Binding::new(execution, runner));
                Ok(())
            }
            Err(error) => refuse(now, runner, error, connection),
        }
    }

    /// Remembers that the host started `key`, the latest generation of its ID, and forgets the
    /// ID that it heard of first once it remembers more than [`MAX_HISTORY`].
    fn remember(&mut self, key: Key) {
        if self
            .generations
            .insert(key.id(), key.generation())
            .is_none()
        {
            self.history.push_back(key.id());
        }
        if self.history.len() > MAX_HISTORY
            && let Some(first) = self.history.pop_front()
        {
            self.generations.remove(&first);
        }
    }
}

impl Drop for Executions {
    /// Drops every execution, and waits a little for their programs, as
    /// [`clear`](Executions::clear) does.
    fn drop(&mut self) {
        self.clear();
    }
}

/// Returns whether the runner of `binding` has not returned its terminal outcome, and otherwise
/// [forgets](forget) the execution.
fn running(binding: &Binding, reaping: &mut Vec<u32>) -> bool {
    if binding.is_finished() {
        forget(binding, reaping);
        return false;
    }
    true
}

/// Adds the process ID of the program of `binding` to `reaping`, unless the execution collected
/// the program's status: the worker drops the binding next, which kills the program if it runs,
/// and collects the program's status once it ended.
fn forget(binding: &Binding, reaping: &mut Vec<u32>) {
    if binding.execution().status().is_none() {
        reaping.push(binding.id());
    }
}

/// Spawns the program of `start` with pipes, in a process group of its own, and returns its
/// execution.
fn spawn(start: &Start) -> io::Result<Execution> {
    let arguments = start
        .arguments
        .iter()
        .map(|argument| CString::new(argument.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let program = arguments.first().cloned().unwrap_or_default();
    let (pipes, ends) = Pipes::new(start.input)?;
    let stdin = match ends.stdin {
        Some(stdin) => stdin,
        None => OwnedFd::from(File::open(NULL_DEVICE)?),
    };
    let spawned = Command::new(program, arguments)
        .stdin(stdin)
        .stdout(ends.stdout)
        .stderr(ends.stderr)
        .new_process_group()
        .spawn()?;
    let id = spawned.id();
    Execution::new(spawned, pipes, Options::new().process_group()).inspect_err(|error| {
        // The execution killed the program, whose status is still the worker's, unless `ESRCH`
        // tells that it is gone already.
        if error.raw_os_error() != Some(Errno::ESRCH as i32) {
            let _ = wait::waitpid(super::pid(id), None);
        }
    })
}

/// Refuses the execution of `runner` at `now`, whose launch failed at stage 0 with `error`: queues
/// its messages on `connection`, its terminal record last.
fn refuse<S: Read + Write + AsFd>(
    now: Instant,
    mut runner: Runner,
    error: i32,
    connection: &mut Connection<S>,
) -> Result<(), ServeError> {
    runner.launched(Err(LaunchFailure::new(0, error)));
    for stream in Stream::ALL {
        runner.output_closed(stream);
    }
    runner.exited(now, None);
    while let Some(request) = runner.next_request() {
        if let runner::Request::Settle = request {
            runner.settled(Settlement::Failed);
        }
    }
    let key = runner.key();
    while let Some(message) = runner.next_message(&mut []) {
        if let Some(message) = GuestMessage::from_runner(key, message, &[]) {
            connection.send(&message.encode())?;
        }
    }
    Ok(())
}

/// Returns the failure of the host's message about the execution `key` that its runner refused.
fn refused(key: Key, violation: Violation) -> ServeError {
    ServeError::Execution(format!("execution {}: {violation}", name(key)))
}

/// Reports a failure of the execution `key` that its binding reported, which ends nothing: the
/// runner's deadlines bound what the failure leaves.
fn report(key: Key, event: &Event) {
    match event {
        Event::KillFailed(target, error) => {
            eprintln!(
                "runtime-adapter-guest: execution {}: cannot kill its {target:?}: {error}",
                name(key)
            );
        }
        Event::SettlementFailed(error) => {
            eprintln!(
                "runtime-adapter-guest: execution {}: cannot settle it: {error}",
                name(key)
            );
        }
        Event::InputFailed(error) => {
            eprintln!(
                "runtime-adapter-guest: execution {}: cannot write its input: {error}",
                name(key)
            );
        }
        _ => {}
    }
}
