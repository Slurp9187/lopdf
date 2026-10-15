//! Removing a PDF's Standard-handler encryption in memory that does not grow with the file: the
//! streaming Strip. See `docs/plans/stream-strip.md`.
//!
//! The Strip reads a `Read + Seek` source through bounded windows, object by object. A file it
//! cannot handle that way fails with [`Error::NeedsWholeDocument`](crate::Error::NeedsWholeDocument)
//! and a [`StripFallback`] saying why; the caller then strips it through the whole-document path.

// Nothing calls the index pass until `strip()` arrives in S5, which must remove this.
#![cfg_attr(not(test), expect(dead_code, reason = "used by strip() from S5 on"))]
#![cfg_attr(test, allow(dead_code, reason = "some tests are compiled out with the async feature"))]

mod index;
mod source;

use std::fmt;

/// Why a file needs the whole-document path rather than the streaming Strip. None of these is an
/// error in the file as such: the whole-document path, which can repair it, may still succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StripFallback {
    /// No `%PDF-` header in the first 1024 bytes.
    NoHeader,
    /// The cross-reference chain cannot be followed from `startxref`, so the file would need its
    /// cross-reference data rebuilt.
    XrefUnresolvable,
    /// More objects than the streaming index holds.
    TooManyObjects,
}

impl fmt::Display for StripFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StripFallback::NoHeader => "no %PDF- header in the first 1024 bytes",
            StripFallback::XrefUnresolvable => "the cross-reference chain cannot be followed",
            StripFallback::TooManyObjects => "more objects than the streaming index holds",
        })
    }
}

/// The bounds that keep the Strip's memory independent of the file. Unlike `LoadOptions`, every
/// one is set: unbounded is not an option here.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Caps {
    /// The most cross-reference entries the index holds.
    pub(crate) max_objects: usize,
    /// The largest window a cross-reference section (a table and its trailer, or a cross-reference
    /// stream object) may need.
    pub(crate) max_section: usize,
    /// The most any one cross-reference or object stream may decompress to.
    pub(crate) max_decoded: usize,
    /// The most all of them together may decompress to.
    pub(crate) max_total_decoded: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            // A classic table entry is 20 bytes, so this holds a section of every object the index
            // may hold, with room for its trailer.
            max_section: 21 * 1024 * 1024,
            max_decoded: 64 * 1024 * 1024,
            max_total_decoded: 256 * 1024 * 1024,
        }
    }
}
