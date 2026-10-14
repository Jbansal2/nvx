//! The process arguments as the kernel passes them: NUL-terminated strings, which the programs
//! read byte by byte without measuring them first.

use core::marker::PhantomData;

/// The arguments of a process: `argc` pointers to NUL-terminated strings.
#[derive(Clone, Copy)]
pub(crate) struct Args<'a> {
    count: usize,
    values: *const *const u8,
    strings: PhantomData<&'a u8>,
}

impl<'a> Args<'a> {
    /// Wraps `argc` and `argv`.
    ///
    /// # Safety
    ///
    /// `values` must point to `count` pointers to NUL-terminated strings, which stay valid and
    /// unchanged for `'a`.
    pub(crate) unsafe fn new(count: usize, values: *const *const u8) -> Self {
        Self {
            count,
            values,
            strings: PhantomData,
        }
    }

    /// Returns argument `index`, or `None` past the last one.
    pub(crate) fn get(self, index: usize) -> Option<Arg<'a>> {
        (index < self.count).then(|| self.arg(index))
    }

    /// Returns the arguments as an array when there are exactly `N`.
    pub(crate) fn exactly<const N: usize>(self) -> Option<[Arg<'a>; N]> {
        (self.count == N).then(|| core::array::from_fn(|index| self.arg(index)))
    }

    fn arg(self, index: usize) -> Arg<'a> {
        debug_assert!(index < self.count);
        Arg {
            // SAFETY: `values` holds `count` pointers, and the index is below the count.
            pointer: unsafe { *self.values.add(index) },
            string: PhantomData,
        }
    }
}

/// An argument: a NUL-terminated string.
#[derive(Clone, Copy)]
pub(crate) struct Arg<'a> {
    pointer: *const u8,
    string: PhantomData<&'a u8>,
}

impl<'a> Arg<'a> {
    /// Returns the address of the string, for the system calls that take a path.
    pub(crate) fn as_ptr(self) -> *const u8 {
        self.pointer
    }

    /// Returns the bytes of the string, without its NUL.
    pub(crate) fn bytes(self) -> Bytes<'a> {
        Bytes {
            pointer: self.pointer,
            string: PhantomData,
        }
    }

    /// Returns whether the string is `text`, as `strcmp` would find.
    pub(crate) fn equals(self, text: &[u8]) -> bool {
        let mut bytes = self.bytes();
        text.iter().all(|&byte| bytes.next() == Some(byte)) && bytes.next().is_none()
    }
}

/// The bytes of an argument, up to its NUL.
pub(crate) struct Bytes<'a> {
    pointer: *const u8,
    string: PhantomData<&'a u8>,
}

impl Iterator for Bytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        // SAFETY: the pointer stays within the string, at most at its NUL.
        let byte = unsafe { *self.pointer };
        if byte == 0 {
            return None;
        }
        // SAFETY: the byte is not the NUL, so the string continues.
        self.pointer = unsafe { self.pointer.add(1) };
        Some(byte)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::ffi::CString;

    use super::*;

    /// Calls `f` with `arguments` as a process's arguments.
    pub(crate) fn with_args<R>(arguments: &[&[u8]], f: impl FnOnce(Args<'_>) -> R) -> R {
        let strings: Vec<CString> = arguments
            .iter()
            .map(|argument| CString::new(*argument).unwrap())
            .collect();
        let pointers: Vec<*const u8> = strings
            .iter()
            .map(|string| string.as_ptr().cast())
            .collect();
        // SAFETY: the pointers point to the strings, which outlive the call.
        f(unsafe { Args::new(strings.len(), pointers.as_ptr()) })
    }

    #[test]
    fn indexes_the_arguments() {
        with_args(&[b"program", b"first", b""], |args| {
            assert!(args.get(0).unwrap().bytes().eq(*b"program"));
            assert!(args.get(1).unwrap().equals(b"first"));
            assert!(args.get(2).unwrap().equals(b""));
            assert!(args.get(3).is_none());
            assert!(args.exactly::<2>().is_none());
            let [program, first, empty] = args.exactly::<3>().unwrap();
            assert!(program.equals(b"program") && first.equals(b"first") && empty.equals(b""));
        });
    }

    #[test]
    fn equals_compares_whole_strings() {
        with_args(&[b"read", b"readable", b"rea"], |args| {
            let [read, readable, rea] = args.exactly::<3>().unwrap();
            assert!(read.equals(b"read"));
            assert!(!readable.equals(b"read"));
            assert!(!rea.equals(b"read"));
            assert!(!read.equals(b"readable"));
        });
    }

    #[test]
    fn as_ptr_is_the_address_of_the_string() {
        let path = c"/dev/port";
        let pointers = [path.as_ptr().cast::<u8>()];
        // SAFETY: the pointer points to the string, which outlives `args`.
        let args = unsafe { Args::new(1, pointers.as_ptr()) };
        assert_eq!(args.get(0).unwrap().as_ptr(), pointers[0]);
    }
}
