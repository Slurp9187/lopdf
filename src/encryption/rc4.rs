use zeroize::Zeroize as _;

// This module exists because the rust-crypto module is really old and not maintained.
// Fortunately the RC4 algorithm is very simple to implement.
pub struct Rc4 {
    initial_state: [u8; 256],
}

/// The key-scheduled state is as good as the key, so it is wiped on drop.
impl Drop for Rc4 {
    fn drop(&mut self) {
        self.initial_state.zeroize();
    }
}

impl Rc4 {
    pub fn new<Key: AsRef<[u8]>>(key: Key) -> Self {
        let key = key.as_ref();
        assert!(!key.is_empty() && key.len() <= 256);

        let mut initial_state = [0_u8; 256];
        for (i, v) in initial_state.iter_mut().enumerate() {
            *v = i as u8;
        }

        let mut j = 0_u8;
        for i in 0..256 {
            j = j.wrapping_add(initial_state[i]).wrapping_add(key[i % key.len()]);
            initial_state.swap(i, j as usize);
        }

        Self { initial_state }
    }

    /// Encrypts/decrypts `input` into `output`.  The shorter of `input` and `output`
    ///  determine how many bytes are written into `output`.
    pub fn apply_keystream<'i, 'o, Input, Output>(&self, input: Input, output: Output)
    where
        Input: Iterator<Item = &'i u8>,
        Output: Iterator<Item = &'o mut u8>,
    {
        let mut state = self.initial_state;
        let mut i = 0_u8;
        let mut j = 0_u8;
        for (i_byte, o_byte) in input.zip(output) {
            i = i.wrapping_add(1);
            j = j.wrapping_add(state[i as usize]);
            state.swap(i as usize, j as usize);
            let key_byte = state[(state[i as usize].wrapping_add(state[j as usize])) as usize];
            *o_byte = i_byte ^ key_byte;
        }
        state.zeroize();
    }

    /// A keystream that carries on from where the last call to
    /// [`Rc4Keystream::apply`] stopped, for data that arrives in chunks.
    pub fn keystream(&self) -> Rc4Keystream {
        Rc4Keystream {
            state: self.initial_state,
            i: 0,
            j: 0,
        }
    }

    /// Allocates a new Vec<u8> of the same length as `input` and decrypts
    ///  `input` into it.
    pub fn decrypt<Input>(&self, input: Input) -> Vec<u8>
    where
        Input: AsRef<[u8]>,
    {
        let input = input.as_ref();
        let mut output = vec![0; input.len()];
        self.apply_keystream(input.iter(), output.iter_mut());
        output
    }

    /// Allocates a new Vec<u8> of the same length as `input` and encrypts
    ///  `input` into it.
    pub fn encrypt<Input>(&self, input: Input) -> Vec<u8>
    where
        Input: AsRef<[u8]>,
    {
        // Rc4 is symmetric
        self.decrypt(input)
    }
}

/// An RC4 keystream part way through, from [`Rc4::keystream`]. Its state is as
/// good as the key, so it is wiped on drop.
pub struct Rc4Keystream {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Drop for Rc4Keystream {
    fn drop(&mut self) {
        self.state.zeroize();
        self.i.zeroize();
        self.j.zeroize();
    }
}

impl Rc4Keystream {
    /// XORs the next `input.len()` bytes of the keystream with `input` into
    /// `output`, which must be at least as long.
    pub fn apply(&mut self, input: &[u8], output: &mut [u8]) {
        for (i_byte, o_byte) in input.iter().zip(output.iter_mut()) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let key_byte = self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
            *o_byte = i_byte ^ key_byte;
        }
    }
}
