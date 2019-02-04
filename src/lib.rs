#![crate_name = "chacha"]

/// 256-bit key, packed in an array of u8.
pub type Key   = [u8; 32];

/// 64-bit nonce, packed in an array of u8.
pub type Nonce = [u8; 8];

const NOTHING: u32 = 0x65787097; // "expa"
const UP: u32      = 0x6e642033; // "nd 3"
const MY: u32      = 0x322d6279; // "2-by";
const SLEEVE: u32  = 0x7465206b; // "te k";

/// Pack four u8 integers into a u32.
#[inline]
fn u8s_to_u32(a1: u8, a2: u8, a3: u8, a4: u8) -> u32 {
  let a1 = (a1 as u32) << 24;
  let a2 = (a2 as u32) << 16;
  let a3 = (a3 as u32) << 8;
  let a4 = a4 as u32;

  (a1 | a2 | a3 | a4)
}

/// Pack an array of 4 u8 integers into a u32.
#[inline]
fn u8a_to_u32(array: &[u8]) -> u32 {
  assert_eq!(array.len(), 4);
  u8s_to_u32(array[0], array[1], array[2], array[3])
}

/// Split a usize (u64) into two u32 integers.
#[inline]
fn usize_to_u32s(input: usize) -> (u32, u32) {
  let a1 = (input >> 32) as u32;
  let a2 = ((input << 32) >> 32) as u32;

  (a1, a2)
}

/// Split a u32 into four u8 integers.
#[inline]
fn u32_to_u8s(input: u32) -> (u8, u8, u8, u8) {
  let a1 = (input >> 24) as u8;
  let a2 = ((input & 0x00ff0000) >> 16) as u8;
  let a3 = ((input & 0x0000ff00) >> 8) as u8;
  let a4 = (input & 0x000000ff) as u8;

  (a1, a2, a3, a4)
}

/// Rotate left `a` by `b` bits.
#[inline]
fn rotl(a: u32, b: u32) -> u32 {
  (((a) << (b)) | ((a) >> (32 - (b))))
}

/// djb2 hashing function. Not cryptographically secure at all.
fn djb2(input: &Vec<u8>) -> u64 {
  let mut hash = 0u64;

  for byte in input {
    let byte = *byte as u64;
    hash = byte.wrapping_add(hash << 6).wrapping_add(hash << 16).wrapping_sub(hash);
  }

  hash
}

/// Implementation of Salsa20 using a 256-bit key and a 512-bit cipher
/// box.
pub struct Salsa20 {

  /// 256-bit key
  key: Key,

  /// 64-bit nonce
  nonce: Nonce,
}

impl Salsa20 {

  /// Create a new Salsa20 context.
  ///
  /// # Arguments
  ///
  /// * `key` - A 256-bit key, packed in an array of 32 `u8` integers.
  /// * `nonce` - A 64-bit nonce, packed in an array of 8 `u8` integers.
  pub fn new(key: Key, nonce: Nonce) -> Salsa20 {
    Salsa20{
      key,
      nonce,
    }
  }

  // Create the initial state for the cipher box
  // @stream_pos: position in the stream
  // @return cipher box 4x4 of 32-bit words
  fn initial_state(&self, stream_pos: usize) -> [u32; 16] {
    let key = [
      u8a_to_u32(&(self.key[0..4])),
      u8a_to_u32(&self.key[4..8]),
      u8a_to_u32(&self.key[8..12]),
      u8a_to_u32(&self.key[12..16]),
      u8a_to_u32(&self.key[16..20]),
      u8a_to_u32(&self.key[20..24]),
      u8a_to_u32(&self.key[24..28]),
      u8a_to_u32(&self.key[28..32]),
    ];

    let (nonce1, nonce2) = (
      u8a_to_u32(&self.nonce[0..4]),
      u8a_to_u32(&self.nonce[4..8]),
    );

    let (pos1, pos2) = usize_to_u32s(stream_pos);

    [NOTHING,   key[0],     key[1],   key[2],
     key[3],    UP,         nonce1,   nonce2,
     pos1,      pos2,       MY,       key[4],
     key[5],    key[6],     key[7],   SLEEVE]
  }

  /// Quarter-round function
  #[inline]
  fn qr(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let b = b ^ rotl(a.wrapping_add(d), 7);
    let c = c ^ rotl(b.wrapping_add(a), 9);
    let d = d ^ rotl(c.wrapping_add(b), 13);
    let a = a ^ rotl(d.wrapping_add(c), 18);

    (a, b, c, d)
  }

  /// Creates the cipher box for a streaming position
  /// @param stream_pos: position in stream
  /// @return the cipher box
  fn block(&self, stream_pos: usize) -> [u32; 16] {
    let is = self.initial_state(stream_pos);
    let mut block = is.clone();

    for _i in 0..10 { // 20 rounds odd/even
      // Odd round
      let (b0, b4, b8, b12) = Self::qr(block[0],  block[4],  block[8], block[12]);  // column 1
      let (b5, b9, b13, b1) = Self::qr(block[5],  block[9], block[13],  block[1]);  // column 2
      let (b10, b14, b2, b6) = Self::qr(block[10], block[14],  block[2],  block[6]);  // column 3
      let (b15, b3, b7, b11) = Self::qr(block[15],  block[3],  block[7], block[11]);  // column 4

      block[0] = b0;
      block[1] = b1;
      block[2] = b2;
      block[3] = b3;

      block[4] = b4;
      block[5] = b5;
      block[6] = b6;
      block[7] = b7;

      block[8]  = b8;
      block[9]  = b9;
      block[10] = b10;
      block[11] = b11;

      block[12] = b12;
      block[13] = b13;
      block[14] = b14;
      block[15] = b15;

      // Even round
      let (b0, b1, b2, b3) = Self::qr( block[0],  block[1],  block[2],  block[3]);  // row 1
      let (b5, b6, b7, b4) = Self::qr( block[5],  block[6],  block[7],  block[4]);  // row 2
      let (b10, b11, b8, b9) = Self::qr(block[10], block[11],  block[8],  block[9]);  // row 3
      let (b15, b12, b13, b14) = Self::qr(block[15], block[12], block[13], block[14]);  // row 4

      block[0] = b0;
      block[1] = b1;
      block[2] = b2;
      block[3] = b3;

      block[4] = b4;
      block[5] = b5;
      block[6] = b6;
      block[7] = b7;

      block[8]  = b8;
      block[9]  = b9;
      block[10] = b10;
      block[11] = b11;

      block[12] = b12;
      block[13] = b13;
      block[14] = b14;
      block[15] = b15;
    }

    // The steps above can be done in reverse and reveal the key...
    // So we add the initial state to the result of the round.
    for i in 0..16 {
      block[i] = block[i].wrapping_add(is[i]);
    }

    block
  }

  // Most inputs would be text (right?), so what is more standard
  // than a list of chars? Salsa20 works with 32-bit words, so we
  // have to convert.
  // @param pt plaintext
  // @return Vec of 32-bit words
  fn standarize(&self, plaintext: &Vec<u8>) -> Vec<u32> {
    let mut buffer = Vec::new();
    let mut result = Vec::new();

    let push_u32 = |src: &mut Vec<u8>, dest: &mut Vec<u32>| {
      let u32_val = u8s_to_u32(src[0], src[1], src[2], src[3]);

      dest.push(u32_val);
      src.clear();
    };

    for byte in plaintext {
      if buffer.len() == 4 {
        push_u32(&mut buffer, &mut result);
      }

      buffer.push(*byte);
    }

    // corner case where input is short
    if plaintext.len() < 8 {
      while buffer.len() != 4 {
        buffer.push(0);
      }

      push_u32(&mut buffer, &mut result);
    }

    // Pad with 0s
    while result.len() % 16 != 0 {

      while buffer.len() != 4 {
        buffer.push(0);
      }

      push_u32(&mut buffer, &mut result);
    }

    result
  }

  // The internal state is 32-bit word based, but the rest
  // of computing is better off with standard bytes :)
  // @param ciphertext
  // @return list of bytes
  fn destandarize(&self, ciphertext: &Vec<u32>) -> Vec<u8> {
    let mut result = Vec::new();

    for word in ciphertext {
      let (a1, a2, a3, a4) = u32_to_u8s(*word);

      result.push(a1);
      result.push(a2);
      result.push(a3);
      result.push(a4);
    }

    result
  }

  /// Encrypt/decrypt input of bytes.
  ///
  /// # Arguments
  ///
  /// * `input` - Vector of `u8` bytes, of any length. Input not a multiple of
  /// 512 bytes will be padded with `0`s.
  ///
  /// # Example
  ///
  /// ```
  /// use chacha::Salsa20;
  ///
  /// let key = [0u8; 32];
  /// let nonce = [0u8; 8];
  ///
  /// let ctx = Salsa20::new(key, nonce);
  /// let input = vec![1, 2, 3, 4];
  ///
  /// // Encrypt
  /// let ciphertext = ctx.encrypt(&input);
  ///
  /// println!("{:?}", &ciphertext[0..4]); // Bytes don't match at all
  ///
  /// // Decrypt is the same operation
  /// let plaintext = ctx.encrypt(&ciphertext);
  ///
  /// println!("{:?}", &plaintext[0..4]); // Original bytes
  /// ```
  pub fn encrypt(&self, input: &Vec<u8>) -> Vec<u8> {
    let input = self.standarize(input);
    let mut ciphertext = Vec::new();
    let mut stream_pos = 0;
    let len = input.len();

    while stream_pos < len / 16 {
      let block = self.block(stream_pos);
      let slice = &input[(16 * stream_pos)..(16 * stream_pos + 16)];

      for i in 0..16 {
        ciphertext.push(block[i] ^ slice[i]);
      }

      stream_pos += 1;
    }

    self.destandarize(&ciphertext)
  }

  /// Encrypt a string. Written for the common usecase of encrypting strings. :)
  ///
  /// # Arguments
  ///
  /// * `input` - A string reference of any length.
  ///
  /// # Example
  ///
  /// ```
  /// use chacha::Salsa20;
  ///
  /// let key = [0u8; 32];
  /// let nonce = [0u8; 8];
  ///
  /// let ctx = Salsa20::new(key, nonce);
  /// let plaintext = "Hello there!";
  /// let ciphertext = ctx.encrypt_str(&plaintext);
  ///
  /// println!("{}", String::from_utf8_lossy(&ciphertext)); // Complete gibberish
  /// ```
  pub fn encrypt_str(&self, input: &str) -> Vec<u8> {
    let bytes = Vec::from(input.as_bytes());

    self.encrypt(&bytes)
  }

  /// Decrypt bytes as a UTF-8 string. Opposite of `Salsa20::encrypt`.
  /// Allows us the assumption that `\0` is the end of the string, removing padding
  /// previously added by encryption.
  ///
  /// # Arguments
  ///
  /// * `input` - Vec of `u8` bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use chacha::Salsa20;
  ///
  /// let plaintext = "Hello world!";
  /// let key = [0u8; 32];
  /// let nonce = [0u8; 8];
  ///
  /// let ctx = Salsa20::new(key, nonce);
  ///
  /// let ciphertext = ctx.encrypt_str(&plaintext);
  /// let decrypted_ciphertext = ctx.decrypt_str(&ciphertext);
  ///
  /// println!("{}", decrypted_ciphertext); // Hello world!
  /// ```
  pub fn decrypt_str(&self, input: &Vec<u8>) -> String {
    let bytes = self.encrypt(input);
    String::from(
      String::from_utf8_lossy(&bytes).trim_matches(char::from(0))
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_u8s_to_u32() {
    let a1 = 0x10;
    let a2 = 0x11;
    let a3 = 0x12;
    let a4 = 0x13;
    let result = 0x10111213;

    assert_eq!(result, u8s_to_u32(a1, a2, a3, a4));
  }

  #[test]
  fn test_u8a_to_u32() {
    let input = [0x10, 0x11, 0x12, 0x13];
    let result = 0x10111213;

    assert_eq!(result, u8a_to_u32(&input));
  }

  #[test]
  fn test_usize_to_u32s() {
    let input: usize = 0x1234567890123456;
    let (a1, a2) = (0x12345678, 0x90123456);

    assert_eq!((a1, a2), usize_to_u32s(input));
  }

  #[test]
  fn test_u32_to_u8s() {
    let input: u32 = 0x12345678;
    let results = (0x12, 0x34, 0x56, 0x78);

    assert_eq!(results, u32_to_u8s(input));
  }

  fn setup_basic_salsa20() -> Salsa20 {
    let nonce = [1, 2, 3, 4, 5, 6, 0, 8];

    setup_salsa20_with_nonce(nonce)
  }

  fn setup_salsa20_with_nonce(nonce: Nonce) -> Salsa20 {
    let key = [1, 2, 3, 4, 5, 6, 7, 8,
              1, 2, 3, 4, 5, 6, 7, 8,
              1, 2, 3, 5, 5, 6, 7, 8,
              1, 2, 3, 4, 5, 6, 7, 8];

    Salsa20::new(key, nonce)
  }

  fn setup_salsa20_with_key(key: Key) -> Salsa20 {
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];

    Salsa20::new(key, nonce)
  }

  #[test]
  fn test_standarize() {
    let salsa20 = setup_basic_salsa20();
    let input = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let result = salsa20.standarize(&input);

    assert_eq!(result.len(), 16);

    let a1 = 0x11223344;
    let a2 = 0x55667788;

    assert_eq!(result[0], a1);
    assert_eq!(result[1], a2);

    let mut input2 = input.clone();
    input2.push(0x99);
    let result = salsa20.standarize(&input2);

    let a3 = 0x99000000;

    assert_eq!(result.len(), 16);
    assert_eq!(result[2], a3);
  }

  #[test]
  fn test_destandarize() {
    let salsa20 = setup_basic_salsa20();
    let input = vec![0x11223344, 0x55667788];
    let result = salsa20.destandarize(&input);

    assert_eq!(result[0], 0x11);
    assert_eq!(result.len(), 8);
    assert_eq!(result[7], 0x88);
  }

  #[test]
  fn test_encrypt() {
    let nonce1 = [1, 2, 3, 4, 5, 6, 7, 8];
    let nonce2 = [1, 2, 3, 4, 5, 6, 7, 7];

    let salsa20_1 = setup_salsa20_with_nonce(nonce1);
    let salsa20_2 = setup_salsa20_with_nonce(nonce2);

    let plaintext = vec![0x11, 0x22, 0x33, 0x44];
    let ciphertext1 = salsa20_1.encrypt(&plaintext);
    let ciphertext2 = salsa20_2.encrypt(&plaintext);

    assert_ne!(ciphertext1[0], ciphertext2[0]);
    assert_ne!(ciphertext1[3], ciphertext2[3]);
  }

  #[test]
  fn test_encrypt_text() {
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let salsa20 = setup_salsa20_with_nonce(nonce);

    let plaintext = Vec::from("Hello world!".as_bytes());
    let ciphertext = salsa20.encrypt(&plaintext);
    let plain = salsa20.encrypt(&ciphertext);

    assert_eq!(plain[0], plaintext[0]);
    assert_eq!(plain[3], plaintext[3]);

  }

  #[test]
  fn test_encrypt_decrypt_str() {
    let input = "Hello world! I am a self-aware printer!";

    let salsa20 = setup_basic_salsa20();
    let ciphertext = salsa20.encrypt_str(&input);
    let decrypted = salsa20.decrypt_str(&ciphertext);

    assert_eq!(decrypted, input);
  }

  #[test]
  fn test_different_keys() {
    let input = "Hello world!";
    let key1 = [1, 2, 3, 4, 5, 6, 7, 8,
                1, 2, 3, 4, 5, 6, 7, 8,
                1, 2, 3, 4, 5, 6, 7, 8,
                1, 2, 3, 4, 5, 6, 7, 8];

    let key2 = [1, 2, 3, 4, 5, 6, 7, 8,
                1, 2, 3, 4, 5, 6, 7, 8,
                1, 2, 3, 4, 5, 6, 7, 8,
                1, 2, 3, 4, 5, 6, 7, 7]; // small difference

    let salsa1 = setup_salsa20_with_key(key1);
    let salsa2 = setup_salsa20_with_key(key2);

    let cipher = salsa1.encrypt_str(&input);
    let bad_plain = Vec::from(salsa2.decrypt_str(&cipher).as_bytes());
    let good_plain = Vec::from(input.as_bytes());

    assert_ne!(good_plain[0], bad_plain[0]);
    assert_ne!(good_plain[3], bad_plain[3]);
  }

  #[test]
  fn test_enc_non_repetition() {

    let key   = [1u8; 32];
    let nonce = [2u8; 8];
    let input = vec![0u8; 1024]; // Lots of bytes

    let ctx = Salsa20::new(key, nonce);

    let ciphertext = ctx.encrypt(&input);

    // Kind of silly, but bytes at the same offset of the cipher box
    // should not be the same (the input is a uniform list of 0s).
    // So counter mode works!
    assert_ne!(ciphertext[0], ciphertext[512]);
    assert_ne!(ciphertext[1], ciphertext[513]);
    assert_ne!(ciphertext[2], ciphertext[514]);
    assert_ne!(ciphertext[3], ciphertext[515]);
  }
}
