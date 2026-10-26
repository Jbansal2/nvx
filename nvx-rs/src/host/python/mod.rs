//! Python semantics that the faithful ports of `scripts/nvx.py` tools need.
//!
//! Commands that `nvx.py` delegates to `nvx-rs` keep the behavior of the Python code they
//! replace, which depends on how Python reads JSON and integers, holds and prints strings and
//! paths, and queries the filesystem. These modules implement what the ports rely on, after
//! CPython 3.14:
//!
//! - [`text`]: Python strings, which may hold unpaired surrogates, how Python prints them, and
//!   the errors of its UTF-8 codec.
//! - [`builtins`]: `str.isspace`, `str.split()`, `str.strip()`, `repr` of a `str`, and `int`.
//! - [`json`]: a JSON reader that accepts what `json.loads` accepts, with the equivalents of its
//!   `object_pairs_hook` and `parse_int` hooks, and that fails with its messages.
//! - [`path`]: `str(pathlib.Path(...))`, which Python messages show, and the pure paths of
//!   `pathlib` with the `os.path` operations that they use.
//!
//! The CLI reads and writes its JSON with `serde_json`, its integers as ASCII decimals, and its
//! arguments with its own parser, and holds host paths with `std::path`, as
//! [`crate::host::paths`] spells them, so these modules serve only the golden tests of these
//! semantics.
//!
//! Character properties come from the Unicode 16.0.0 database of Python 3.14, in [`unicode`],
//! which `scripts/nvx_rs_fixtures.py` generated. The same script recorded what Python does with
//! fixed and seeded random inputs in `tests/fixtures`, and the golden tests compare these
//! implementations, and the ports that use them, with those records. microsoft/nvx#359 retired
//! the script with the Python code that it recorded, so the records are frozen.

#[cfg(test)]
pub(crate) mod builtins;
#[cfg(test)]
pub(crate) mod golden;
#[cfg(test)]
pub(crate) mod json;
#[cfg(test)]
pub(crate) mod path;
#[cfg(test)]
pub(crate) mod text;
#[cfg(test)]
pub(crate) mod unicode;
#[cfg(test)]
pub(crate) mod uuid;
