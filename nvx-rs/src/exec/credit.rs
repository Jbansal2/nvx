//! The credit arithmetic of an execution's pools, and the bounded queues of its streams.
//!
//! A sender holds [`Credit`]: the units of a pool that the receiver granted it and that it has
//! not used, which it spends on each data message it sends. A receiver holds [`Granted`]: the
//! units that it granted and that the sender has not used yet, which bound each data message it
//! accepts, and the units that its consumer freed, which it grants again. Both start from the
//! pool's window: the receiver's first grant opens the whole window, and a grant can never open
//! more than the window, so the units in flight never exceed it.

use std::collections::VecDeque;

use super::{Unit, Violation, Window};

/// The credit that a receiver granted the sender of one pool.
#[derive(Debug)]
pub(super) struct Credit {
    /// The pool's window.
    window: Window,
    /// The units that the sender may still send.
    available: u32,
}

impl Credit {
    /// Returns the credit of a pool with `window`, before the receiver's first grant.
    pub(super) fn new(window: Window) -> Self {
        Self {
            window,
            available: 0,
        }
    }

    /// Adds a grant of `units`. A grant of no units, or of more than the units in flight, which
    /// would leave the sender more than the window, is refused and changes nothing.
    pub(super) fn grant(&mut self, units: u32) -> Result<(), Violation> {
        if units == 0
            || u64::from(self.available) + u64::from(units) > u64::from(self.window.size())
        {
            return Err(Violation::Credit);
        }
        self.available += units;
        Ok(())
    }

    /// Returns how many of the first `length` queued bytes one data message may carry now: as
    /// many as the bytes of credit, or all of them while a frame of credit is left.
    pub(super) fn sendable(&self, length: usize) -> usize {
        match self.window.unit() {
            Unit::Bytes => length.min(self.available as usize),
            Unit::Frames if self.available > 0 => length,
            Unit::Frames => 0,
        }
    }

    /// Spends the credit of one data message of `length` bytes, which
    /// [`sendable`](Self::sendable) allowed.
    pub(super) fn spend(&mut self, length: usize) {
        self.available -= self.window.cost(length);
    }
}

/// What the receiver of one pool granted, and what its consumer freed.
#[derive(Debug)]
pub(super) struct Granted {
    /// The pool's window.
    window: Window,
    /// The units that the sender may still send: granted, and not used yet.
    open: u32,
    /// The units that the consumer freed, or that the receiver never granted, which it grants
    /// next.
    returnable: u32,
}

impl Granted {
    /// Returns the window of a pool before its first grant, which opens the whole window.
    pub(super) fn new(window: Window) -> Self {
        Self {
            window,
            open: 0,
            returnable: window.size(),
        }
    }

    /// Charges a data message of `length` bytes, which the caller checked against the maximum
    /// chunk. A message beyond the units that remain open is refused and changes nothing.
    pub(super) fn charge(&mut self, length: usize) -> Result<(), Violation> {
        let cost = self.window.cost(length);
        if cost > self.open {
            return Err(Violation::Window);
        }
        self.open -= cost;
        Ok(())
    }

    /// Frees `units` that the consumer took, to grant them again.
    pub(super) fn free(&mut self, units: u32) {
        self.returnable += units;
    }

    /// Returns the units to grant now, if any, and opens them.
    pub(super) fn take_grant(&mut self) -> Option<u32> {
        let units = std::mem::take(&mut self.returnable);
        self.open += units;
        (units > 0).then_some(units)
    }
}

/// The bytes that one stream's receiver holds for its consumer, in order, with the bounds of the
/// frames that they arrived in when the pool counts frames.
#[derive(Debug)]
pub(super) struct Inbox {
    /// What the pool counts.
    unit: Unit,
    /// The bytes, in order.
    bytes: VecDeque<u8>,
    /// The bytes left of each frame that the inbox holds, oldest first, when the pool counts
    /// frames.
    frames: VecDeque<usize>,
}

impl Inbox {
    /// Returns an empty inbox of a pool that counts `unit`.
    pub(super) fn new(unit: Unit) -> Self {
        Self {
            unit,
            bytes: VecDeque::new(),
            frames: VecDeque::new(),
        }
    }

    /// Returns the number of bytes held.
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the inbox holds nothing.
    pub(super) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Appends one data message, which its pool charged.
    pub(super) fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
        if self.unit == Unit::Frames {
            self.frames.push_back(bytes.len());
        }
    }

    /// Returns the bytes at the front, as many as are contiguous: a part of what the inbox holds
    /// while it holds anything.
    pub(super) fn front(&self) -> &[u8] {
        self.bytes.as_slices().0
    }

    /// Removes the first `count` bytes, at most as many as the inbox holds, and returns the units
    /// that this frees: each byte, or each frame whose last byte it removes.
    pub(super) fn pop(&mut self, count: usize) -> u32 {
        let count = count.min(self.bytes.len());
        self.bytes.drain(..count);
        match self.unit {
            Unit::Bytes => units(count),
            Unit::Frames => {
                let mut left = count;
                let mut freed = 0;
                while left > 0 {
                    let Some(frame) = self.frames.front_mut() else {
                        break;
                    };
                    let taken = left.min(*frame);
                    *frame -= taken;
                    left -= taken;
                    if *frame == 0 {
                        self.frames.pop_front();
                        freed += 1;
                    }
                }
                freed
            }
        }
    }

    /// Removes everything, releases the storage, and returns how many bytes it removed and the
    /// units that this frees.
    pub(super) fn clear(&mut self) -> (usize, u32) {
        let length = self.bytes.len();
        let freed = self.pop(length);
        self.bytes = VecDeque::new();
        (length, freed)
    }
}

/// Returns `count` bytes as units of a byte pool, which a chunk's bound keeps within `u32`.
pub(super) fn units(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Moves the first bytes of `queue` into `buffer`, at most `length` of them, and returns how
/// many it moved.
pub(super) fn take(queue: &mut VecDeque<u8>, buffer: &mut [u8], length: usize) -> usize {
    let length = length.min(buffer.len()).min(queue.len());
    let (first, second) = queue.as_slices();
    let head = length.min(first.len());
    buffer[..head].copy_from_slice(&first[..head]);
    buffer[head..length].copy_from_slice(&second[..length - head]);
    queue.drain(..length);
    length
}
