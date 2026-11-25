use std::io::{self, Read, Seek, SeekFrom};
use zeroize::Zeroizing;

/// A `Read + Seek` source read through windows at given offsets. Each window is allocated at its
/// exact size and never grows, and it is wiped on drop: once decrypted, what a window held may
/// be plaintext. No `BufReader`, whose buffer is never wiped.
pub(crate) struct Source<R> {
    inner: R,
    len: u64,
}

impl<R: Read + Seek> Source<R> {
    pub(crate) fn new(mut inner: R) -> io::Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self { inner, len })
    }

    /// The length of the source in bytes.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Up to `max` bytes at `offset`: fewer only where the source ends, none past its end.
    pub(crate) fn window(&mut self, offset: u64, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        let available = usize::try_from(self.len.saturating_sub(offset)).unwrap_or(usize::MAX);
        let mut window = Zeroizing::new(vec![0; available.min(max)]);
        if !window.is_empty() {
            self.inner.seek(SeekFrom::Start(offset))?;
            self.inner.read_exact(&mut window)?;
        }
        Ok(window)
    }

    /// Fills `buffer` from `offset`, which must leave that many bytes in the source.
    pub(crate) fn read_into(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::Source;
    use std::io::Cursor;

    #[test]
    fn a_window_stops_where_the_source_ends() {
        let mut source = Source::new(Cursor::new(b"0123456789".to_vec())).unwrap();
        assert_eq!(source.len(), 10);
        assert_eq!(source.window(2, 3).unwrap().as_slice(), b"234");
        assert_eq!(source.window(8, 5).unwrap().as_slice(), b"89");
        assert!(source.window(10, 5).unwrap().is_empty());
        assert!(source.window(25, 5).unwrap().is_empty());
    }
}
