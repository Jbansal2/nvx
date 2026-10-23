//! The worker's executions, as the worker's module documentation describes them: the table that
//! reaches each one by its ID, the generations that the host started, their admission, the
//! refusal of a start, the loop's turns at every execution, the collection of each program's
//! status, before which the worker ends what is left of the program's process group, and that of
//! the statuses of the programs that the worker forgot.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{self, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{self, WaitPidFlag, WaitStatus};
use nvx::exec::{Key, LaunchFailure, Runner, Settlement, Stream, Violation, runner};
use nvx::guest::exec::binding::{Binding, Event};
use nvx::guest::exec::{Execution, Options, Pipes, Source};
use nvx::guest::process::Child;
use nvx::guest::spawn::Command;

use super::connection::{BACKLOG, Connection};
use super::{MAX_EXECUTION_MEMORY, MAX_EXECUTIONS, MAX_HISTORY};
use crate::exec::{GuestMessage, HostMessage, MAX_CHUNK, Start, name};
use crate::guest::ServeError;

/// The device that a program without the host's input reads.
const NULL_DEVICE: &str = "/dev/null";

/// The interval at which the worker checks whether the programs that it forgot ended.
const REAP_INTERVAL: Duration = Duration::from_millis(10);

/// The longest that the worker waits for the programs of the executions that it drops at once.
const REAP_WAIT: Duration = Duration::from_secs(1);

/// The most bytes of output that an execution that the host reaches reads in one turn of the
/// loop, give or take a chunk: an equal share of the [`BACKLOG`] among the most executions that
/// the worker runs, so that no execution takes the room on the stream to the host from the
/// others.
const SHARE: usize = BACKLOG / MAX_EXECUTIONS;

/// The worker's executions.
pub(super) struct Executions {
    /// The executions that the host reaches, by ID.
    attached: BTreeMap<u64, Run>,
    /// The executions that the host abandoned, which run until they end.
    detached: Vec<Run>,
    /// The process IDs of the programs that the worker forgot before it collected their
    /// statuses, which it collects once they ended.
    reaping: Vec<u32>,
    /// When the worker last checked whether those programs ended.
    reaped: Option<Instant>,
    /// When the worker stops waiting for the programs once it dropped every execution: a while
    /// after it first did.
    cleared: Option<Instant>,
    /// The ID from which the next turn serves the executions that the host reaches, before
    /// those of lower IDs: the ID after that of the execution that the last turn served first,
    /// so that the executions take turns at being served first.
    turn: u64,
    /// The instant of the last turn if an execution read its whole share of output in it, and
    /// may have more to read: the executions' deadline, which the worker's next wait finds
    /// passed already.
    owed: Option<Instant>,
    /// The latest generation that the host started of each ID of `history`.
    generations: BTreeMap<u64, u64>,
    /// The IDs whose latest generation the worker remembers, in the order in which it heard of
    /// them first.
    history: VecDeque<u64>,
    /// The buffer into which each read of an output stream goes: a chunk at most.
    buffer: Vec<u8>,
}

/// One of the worker's executions: the binding of its runner to its program, which leaves the
/// program's status to the worker, and the worker's own handle of the program.
struct Run {
    /// The binding of the execution's runner to its program.
    binding: Binding,
    /// The program, through a pidfd of the worker's own, which polls readable once the program
    /// ended, until the worker collected its status.
    program: Option<Child>,
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
            turn: 0,
            owed: None,
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
        let Some(run) = self.attached.get_mut(&key.id()) else {
            return Ok(());
        };
        let binding = &mut run.binding;
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

    /// Takes a turn at `now`: collects the status of each program that ended, takes every step
    /// that the executions can take, queues their messages for the host on `connection`,
    /// forgets each execution once it returned its terminal outcome, and collects the statuses
    /// of the programs that it forgot, of those that ended.
    ///
    /// The executions that the host reaches take turns at being served first: a turn starts with
    /// the execution after the one that the last turn started with, in the order of their IDs,
    /// and goes on with the others in that order, starting over from the lowest ID. Each reads at
    /// most [`SHARE`] bytes of output in a turn, and none while the connection is backlogged,
    /// and then returns only its other messages. So, however fast a program writes, and however
    /// much credit the host grants it, the other executions get to the stream in their turns.
    pub(super) fn run<S: Read + Write + AsFd>(
        &mut self,
        now: Instant,
        connection: &mut Connection<S>,
    ) -> Result<(), ServeError> {
        for run in self.attached.values_mut().chain(&mut self.detached) {
            run.collect();
        }
        let Self {
            attached,
            detached,
            reaping,
            turn,
            owed,
            buffer,
            ..
        } = self;
        let first = attached
            .range(*turn..)
            .chain(attached.range(..*turn))
            .next()
            .map(|(&id, _)| id);
        let mut more = false;
        for (_, run) in attached.range_mut(*turn..) {
            more |= run.serve(now, connection, buffer)?;
        }
        for (_, run) in attached.range_mut(..*turn) {
            more |= run.serve(now, connection, buffer)?;
        }
        if let Some(first) = first {
            *turn = first.wrapping_add(1);
        }
        *owed = more.then_some(now);
        attached.retain(|_, run| running(run, reaping));
        for run in detached.iter_mut() {
            let key = run.binding.runner().key();
            while let Some(event) = run.binding.next(now, buffer) {
                // A detached runner returns only its terminal outcome, which no host takes.
                if !matches!(event, Event::Message(_)) {
                    report(key, &event);
                }
            }
        }
        detached.retain(|run| running(run, reaping));
        self.reap(now);
        Ok(())
    }

    /// Abandons every execution at `now`, because the session was reset.
    pub(super) fn reset(&mut self, now: Instant) {
        for (_, mut run) in std::mem::take(&mut self.attached) {
            run.binding.reset(now);
            self.detached.push(run);
        }
    }

    /// Drops every execution, which ends the program and its process group of each one whose
    /// program's status the worker has not collected, and waits for those programs to end, so
    /// that the worker collects their statuses, at most [`REAP_WAIT`] after it first dropped
    /// every execution: a later call, as once the executions drop after a stop, waits no longer.
    /// The worker ended the process groups of the others when it collected their programs'
    /// statuses.
    pub(super) fn clear(&mut self) {
        let Self {
            attached,
            detached,
            reaping,
            ..
        } = self;
        for run in std::mem::take(attached)
            .into_values()
            .chain(detached.drain(..))
        {
            forget(&run, reaping);
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
    /// when the worker checks next whether the programs that it forgot ended, or, if an
    /// execution read its whole share of output in the last turn, that turn's instant, so that
    /// the next turn comes at once.
    pub(super) fn deadline(&self) -> Option<Instant> {
        let reaping = self
            .reaped
            .filter(|_| !self.reaping.is_empty())
            .map(|reaped| reaped + REAP_INTERVAL);
        self.runs()
            .filter_map(|run| run.binding.deadline())
            .chain(reaping)
            .chain(self.owed)
            .min()
    }

    /// Appends the executions' descriptors to `descriptors`, each with the readiness that it
    /// waits for, but those of the output of the executions that the host reaches while the
    /// connection is `backlogged`, as they take no output then, and the pidfd of each program
    /// whose status the worker has not collected, which polls readable once the program ended.
    pub(super) fn poll_descriptors<'a>(
        &'a self,
        descriptors: &mut Vec<PollFd<'a>>,
        backlogged: bool,
    ) {
        let attached = self.attached.values().map(|run| (run, backlogged));
        let detached = self.detached.iter().map(|run| (run, false));
        for (run, backlogged) in attached.chain(detached) {
            for (source, descriptor) in run.binding.descriptors() {
                if !(backlogged && matches!(source, Source::Output(_))) {
                    descriptors.push(PollFd::new(descriptor, PollFlags::POLLIN));
                }
            }
            if let Some(descriptor) = run.binding.input_writer() {
                descriptors.push(PollFd::new(descriptor, PollFlags::POLLOUT));
            }
            if let Some(pidfd) = run.program.as_ref().and_then(Child::pidfd) {
                descriptors.push(PollFd::new(pidfd, PollFlags::POLLIN));
            }
        }
    }

    /// Returns every execution.
    fn runs(&self) -> impl Iterator<Item = &Run> {
        self.attached.values().chain(&self.detached)
    }

    /// Collects at `now` the statuses of the programs that the worker forgot, of those that
    /// ended.
    fn reap(&mut self, now: Instant) {
        self.reaping.retain(|&id| {
            // Any other result tells that no status is left to collect: `ECHILD`, or a status
            // that `nix` collected, and then could not decode, as that of a real-time signal.
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
            .map(|run| run.binding.runner().key().generation());
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
            abandoned.binding.dropped(now);
            self.detached.push(abandoned);
        }
        let runner = Runner::new(key, start.limits, start.timers, now);
        let executions = self.attached.len() + self.detached.len() + self.reaping.len();
        let admitted = if executions >= MAX_EXECUTIONS {
            Err(Errno::EAGAIN as i32)
        } else if runner.memory_bound() > MAX_EXECUTION_MEMORY {
            Err(Errno::ENOMEM as i32)
        } else {
            spawn(&start, &mut self.reaping).map_err(|error| error.raw_os_error().unwrap_or(0))
        };
        match admitted {
            Ok((execution, program)) => {
                let binding = Binding::new(execution, runner);
                let program = Some(program);
                self.attached.insert(key.id(), Run { binding, program });
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

impl Run {
    /// Collects the program's status without blocking once the program ended, and hands it to
    /// the binding. First, it kills what is left of the process group that the program leads, as
    /// the binding's settlement through a cgroup kills what is left in the cgroup, so that no
    /// descendant that stayed in the group outlives the program, or holds its output open: until
    /// its status is collected, the program, a zombie, keeps its process ID, which is the
    /// group's, from any other process, so that the kill reaches that group alone.
    fn collect(&mut self) {
        let Self { binding, program } = self;
        let Some(child) = program else {
            return;
        };
        let Some(pidfd) = child.pidfd() else {
            return;
        };
        // The pidfd polls readable once the program ended, while its status waits to be
        // collected. A wait with `WNOWAIT` would tell that too, but `nix` decodes the status that
        // it reports, which fails for a real-time signal, while the handle's own collection
        // keeps every signal.
        let ended = {
            let mut descriptors = [PollFd::new(pidfd, PollFlags::POLLIN)];
            poll::poll(&mut descriptors, PollTimeout::ZERO).map(|_| {
                descriptors[0]
                    .revents()
                    .is_some_and(|events| events.contains(PollFlags::POLLIN))
            })
        };
        match ended {
            Ok(true) => {}
            Ok(false) | Err(Errno::EINTR) => return,
            Err(error) => {
                // Only the worker collects its programs' statuses, so no wait fails, but the
                // execution's deadlines bound one that does: the worker no longer waits for its
                // program then.
                lost(binding, &error.into());
                *program = None;
                return;
            }
        }
        let id = child.id();
        if let Err(error) = signal::killpg(super::pid(id), Signal::SIGKILL)
            && error != Errno::ESRCH
        {
            eprintln!(
                "runtime-adapter-guest: execution {}: cannot kill its program's process group: \
                 {error}",
                name(binding.runner().key())
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                binding.observe(id, status);
                *program = None;
            }
            Ok(None) => {}
            Err(error) => {
                lost(binding, &error);
                *program = None;
            }
        }
    }

    /// Serves the execution in a turn at `now`: takes every step that it can take, and queues its
    /// messages for the host on `connection`. Each read of its program's output goes into
    /// `buffer`, until it read [`SHARE`] bytes in the turn, or while the connection is
    /// backlogged: an empty buffer then lets it read no output, and return none. Returns whether
    /// it read its whole share, and so may have more output to read in the next turn.
    fn serve<S: Read + Write + AsFd>(
        &mut self,
        now: Instant,
        connection: &mut Connection<S>,
        buffer: &mut [u8],
    ) -> Result<bool, ServeError> {
        let key = self.binding.runner().key();
        let mut read = 0;
        loop {
            let length = if read >= SHARE || connection.is_backlogged() {
                0
            } else {
                buffer.len()
            };
            let lent = &mut buffer[..length];
            let Some(event) = self.binding.next(now, lent) else {
                break;
            };
            match event {
                Event::Message(message) => {
                    if let runner::Message::Output { length: bytes, .. } = message {
                        read += bytes;
                    }
                    if let Some(message) = GuestMessage::from_runner(key, message, lent) {
                        connection.send(&message.encode())?;
                    }
                }
                event => report(key, &event),
            }
        }
        Ok(read >= SHARE)
    }
}

/// Returns whether the runner of `run` has not returned its terminal outcome, and otherwise
/// [forgets](forget) the execution.
fn running(run: &Run, reaping: &mut Vec<u32>) -> bool {
    if run.binding.is_finished() {
        forget(run, reaping);
        return false;
    }
    true
}

/// Adds the process ID of the program of `run` to `reaping`, unless the worker collected the
/// program's status: the worker drops the execution next, whose binding kills the program and its
/// process group, which the program's ID still names, and the worker collects the program's
/// status once the program ended.
fn forget(run: &Run, reaping: &mut Vec<u32>) {
    if run.binding.execution().status().is_none() {
        reaping.push(run.binding.id());
    }
}

/// Spawns the program of `start` with pipes, in a process group of its own, and returns its
/// execution, which leaves the program's status to the worker, with the worker's own handle of
/// the program. If the program started, but the execution or the handle could not be had, the
/// program and its process group end, and the program's ID goes to `reaping`, so that the worker
/// collects its status once it ended, without waiting for it.
fn spawn(start: &Start, reaping: &mut Vec<u32>) -> io::Result<(Execution, Child)> {
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
    let options = Options::new().process_group().caller_reaps();
    let execution = Execution::new(spawned, pipes, options).inspect_err(|error| {
        // The execution ended the program and its process group, and the program's status is
        // still the worker's, unless `ESRCH` tells that it is gone already.
        if error.raw_os_error() != Some(Errno::ESRCH as i32) {
            reaping.push(id);
        }
    })?;
    // Nothing collected the program's status, so its ID still names it. Dropping the execution
    // after a failure ends the program and its process group.
    let program = Child::with_pidfd(id).inspect_err(|_| reaping.push(id))?;
    Ok((execution, program))
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

/// Reports that the worker cannot collect the status of the program of `binding`'s execution,
/// with `error`: the worker no longer waits for the program, and the runner's deadlines bound
/// the execution.
fn lost(binding: &Binding, error: &io::Error) {
    eprintln!(
        "runtime-adapter-guest: execution {}: cannot collect its program's status: {error}",
        name(binding.runner().key())
    );
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
