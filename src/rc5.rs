/*!
 # RC5 block-cipher

 Library implementation of the basic RC5 block cipher in Rust. RC5 is different
 from the classical ciphers (like AES) in the sense that allows to parametrize
 the algorithm and optimize both security and efficiency on different hardware.

 These parameters are:

 * `w`: word length in bytes
 * `r`: number of rounds
 * `b`: key length in bytes

 The selection of each of them should be preferably done by choosing standards
 from other use cases. For example the word length `w` could be any number of
 bytes but the recommendation for performance and security is that should be a
 power of 2, or even better, a power of 8. In that way one can use the hardware
 registers more efficiently, e.g. 32-bits or 64-bits registers, with
 vectorization possibilities (AVX on Intel or SVE on ARM).

 This RC5 implementation is designed only for the standard values of `w` (powers
 of 8) making use of the standard Rust types: u8, u16, u32, u64, u128.

 ## Example: encryption

 ```rust
 use rc5_cipher::encrypt;

 let rounds = 12;
 let key = vec![
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
     0x0E, 0x0F,
 ];
 let pt = [0x33221100u32, 0x77665544];

 let ct = encrypt(pt, &key, rounds);

 assert_eq!(ct, [0x9B14DC2Du32, 0x9E8B08CF]);
 ```

 ## Example: decryption

 ```rust
 use rc5_cipher::decrypt;

 let rounds = 12;
 let key = vec![
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
     0x0E, 0x0F,
 ];
 let ct = [0x9B14DC2Du32, 0x9E8B08CF];

 let pt = decrypt(ct, &key, rounds);

 assert_eq!(pt, [0x33221100u32, 0x77665544]);
 ```

 ## Bibliography

 - Rivest original paper: https://www.grc.com/r&d/rc5.pdf
 - C implementation and tests: https://tools.ietf.org/id/draft-krovetz-rc6-rc5-vectors-00.html#rfc.section.4
 - Haskell implementation: https://hackage.haskell.org/package/cipher-rc5-0.1.2.2/docs/src/Crypto-Cipher-RC5.html

*/

use crate::word::Word;

pub fn rotl<W: Word>(x: W, y: W) -> W {
    let w = W::BYTES * 8;
    let a = y & W::from_usize(w - 1);
    if a == W::ZERO {
        x
    } else {
        (x << a) | (x >> (W::from_usize(w) - a))
    }
}

pub fn rotr<W: Word>(x: W, y: W) -> W {
    let w = W::BYTES * 8;
    let a = y & W::from_usize(w - 1);
    if a == W::ZERO {
        x
    } else {
        (x >> a) | (x << (W::from_usize(w) - a))
    }
}

///
/// Encrypts a plaintext `pt` and returns a ciphertext `ct`.
/// The `pt` is an array of two words `W` (u8, u16, u32, u64, u128)
///
/// Example:
///
/// ```rust
/// use rc5_cipher::encrypt;
///
/// let rounds = 12;
/// let key = vec![0x00, 0x01, 0x02, 0x03];
/// let pt  = [0x00u8, 0x01];
///
/// let ct = encrypt(pt, &key, rounds);
///     
/// assert_eq!(ct, [0x21u8, 0x2A]);
/// ```
///
pub fn encrypt<W: Word>(pt: [W; 2], key: &Vec<u8>, rounds: usize) -> [W; 2] {
    let key_exp = expand_key::<W>(key, rounds);
    let mut a = pt[0].wrapping_add(&key_exp[0]);
    let mut b = pt[1].wrapping_add(&key_exp[1]);
    for i in 1..=rounds {
        a = rotl(a ^ b, b).wrapping_add(&key_exp[2 * i]);
        b = rotl(b ^ a, a).wrapping_add(&key_exp[2 * i + 1]);
    }
    [a, b]
}

///
/// Decrypts a ciphertext `ct` and returns a plaintext `pt`.
/// The `ct` is an array of two words `W` (u8, u16, u32, u64, u128)
///
/// Example:
///
/// ```rust
/// use rc5_cipher::decrypt;
///
/// let rounds = 12;
/// let key = vec![0x00, 0x01, 0x02, 0x03];
/// let ct  = [0x21u8, 0x2A];
///
/// let pt = decrypt(ct, &key, rounds);
///
/// assert_eq!(pt, [0x00u8, 0x01]);
/// ```
///
#[allow(arithmetic_overflow)]
pub fn decrypt<W: Word>(ct: [W; 2], key: &Vec<u8>, rounds: usize) -> [W; 2] {
    let key_exp = expand_key::<W>(key, rounds);
    let mut a = ct[0];
    let mut b = ct[1];
    for i in (1..=rounds).rev() {
        b = rotr(b.wrapping_sub(&key_exp[2 * i + 1]), a) ^ a;
        a = rotr(a.wrapping_sub(&key_exp[2 * i]), b) ^ b;
    }
    [a.wrapping_sub(&key_exp[0]), b.wrapping_sub(&key_exp[1])]
}

///
/// Expands `key` into and array of length `T` of type `W`
///
/// `W`: is the data type. Currently supported: u8, u16, u32, u64, u128
/// `T`: is the key expansion length `T = 2 * (r + 1)` being `r` number of
/// rounds. `T` should be even.
///
/// Example:
///
/// ```rust
/// use rc5_cipher::expand_key;
///
/// let rounds = 1;
/// let key = vec![0x00, 0x01, 0x02, 0x03];
/// let key_exp = expand_key::<u32>(&key, rounds);
///
/// assert_eq!(
///     &key_exp[..],
///     [0xbc13a1cf, 0xfeda18e9, 0x39252ff2, 0x57a51ad8]
/// );
/// ```
///
#[allow(arithmetic_overflow)]
pub fn expand_key<W: Word>(key: &Vec<u8>, rounds: usize) -> Vec<W> {
    let t = 2 * (rounds + 1);
    let b = key.len();
    let w = W::BYTES * 8;

    // c = max(1, ceil(8*b/w))
    let c = std::cmp::max(1, (8 * b + w - 1) / w);

    // converting the secrey key from bytes to words
    let mut key_l: Vec<W> = vec![W::ZERO; c];
    let u = W::BYTES;
    for i in (0..b).rev() {
        let ix = i / u;
        key_l[ix] = (key_l[ix].wrapping_shl(8u32)).wrapping_add(&W::from_u8(key[i]));
    }

    // initializing array S
    let mut key_s = vec![W::ZERO; t];
    key_s[0] = W::P;
    for i in 1..t {
        key_s[i] = key_s[i - 1].wrapping_add(&W::Q);
    }

    // Mixing in the secret key
    let mut i = 0;
    let mut j = 0;
    let mut a = W::ZERO;
    let mut b = W::ZERO;
    for _k in 0..3 * std::cmp::max(c, t) {
        key_s[i] = rotl(key_s[i].wrapping_add(&a.wrapping_add(&b)), W::from_usize(3));
        a = key_s[i];
        key_l[j] = rotl(
            key_l[j].wrapping_add(&a.wrapping_add(&b)),
            a.wrapping_add(&b),
        );
        b = key_l[j];
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
    key_s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_right_shift() {
        let a = 0x77u8; // 0111 0111

        assert_eq!(rotl(a, 1u8), 0xeeu8);
        assert_eq!(rotl(a, 7u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotl(a, 8u8), a);
        assert_eq!(rotl(a, 2 * 8u8), a);
        assert_eq!(rotl(a, 5 * 8u8), a);
        assert_eq!(rotl(a, 1u8), 0xeeu8); // 1110 1110 = 0xee
        assert_eq!(rotl(a, 7u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotr(a, 8u8), a);

        assert_eq!(rotr(a, 1u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotr(a, 2u8), 0xddu8); // 1101 1101 = 0xdd
        assert_eq!(rotr(a, 7u8), 0xeeu8); // 1110 1110 = 0xee
        assert_eq!(rotr(a, 8u8), a);
        assert_eq!(rotr(a, 8u8 + 1u8), 0xbbu8);
        assert_eq!(rotr(a, 8u8 + 2u8), 0xddu8);
        assert_eq!(rotr(a, 8u8 + 7u8), 0xeeu8);
        assert_eq!(rotr(a, 2 * 8u8), a);
        assert_eq!(rotr(a, 5 * 8u8), a);
    }

    #[test]
    fn test_rivest_1() {
        let key = vec![
            0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let pt = [0x00000000u32, 0x00000000];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xEEDBA521u32, 0x6D8F4B15]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0x00000000u32, 0x00000000]);
    }

    #[test]
    fn test_rivest_2() {
        let key = vec![
            0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9,
            0xCE, 0x91,
        ];
        let pt = [0xEEDBA521u32, 0x6D8F4B15];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xAC13C0F7u32, 0x52892B5B]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xEEDBA521u32, 0x6D8F4B15]);
    }

    #[test]
    fn test_rivest_3() {
        let key = vec![
            0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1,
            0x67, 0x87,
        ];
        let pt = [0xAC13C0F7u32, 0x52892B5B];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xB7B3422Fu32, 0x92FC6903]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xAC13C0F7u32, 0x52892B5B]);
    }

    #[test]
    fn test_rivest_4() {
        let key = vec![
            0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1,
            0x2B, 0xAF,
        ];
        let pt = [0xB7B3422Fu32, 0x92FC6903];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xB278C165u32, 0xCC97D184]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xB7B3422Fu32, 0x92FC6903]);
    }

    #[test]
    fn test_rivest_5() {
        let key = vec![
            0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15,
            0x31, 0x25,
        ];
        let pt = [0xB278C165u32, 0xCC97D184];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0x15E444EBu32, 0x249831DA]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xB278C165u32, 0xCC97D184]);
    }

    #[test]
    fn encrypt_decrypt_a() {
        let rounds = 12;
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x33221100u32, 0x77665544];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(ct, [0x9B14DC2Du32, 0x9E8B08CF]);

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(pt, [0x33221100u32, 0x77665544]);
    }

    #[test]
    fn encrypt_decrypt_b() {
        let rounds = 12;
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = [0x144702EAu32, 0x844D5CAD];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(ct, [0x863BE411u32, 0x64EA31D2]);

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(pt, [0x144702EAu32, 0x844D5CAD]);
    }

    // Test cases from https://tools.ietf.org/id/draft-krovetz-rc6-rc5-vectors-00.html#rfc.section.4

    #[test]
    fn encrypt_decrypt_8_12_4() {
        let rounds = 12;
        let key = vec![0x00, 0x01, 0x02, 0x03];

        let pt = [0x00u8, 0x01];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(ct, [0x21u8, 0x2A]);

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(pt, [0x00u8, 0x01]);
    }

    #[test]
    fn encrypt_16_16_8() {
        let rounds = 16;
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let pt = [0x0100u16, 0x0302];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(ct, [0xA823, 0x2ED7]);

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(pt, [0x0100u16, 0x0302]);
    }

    #[test]
    fn encrypt_decrypt_32_20_16() {
        let rounds = 20;
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x03020100u32, 0x07060504];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(ct, [0x0EDC0E2Au32, 0x73FF3194]);

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(pt, [0x03020100u32, 0x07060504]);
    }

    #[test]
    fn encrypt_64_24_24() {
        let rounds = 24;
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = [0x0706050403020100u64, 0x0F0E0D0C0B0A0908];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(ct, [0x02CEDB0E827267A4u64, 0xDA7871AE32EAAB35]);

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(pt, [0x0706050403020100u64, 0x0F0E0D0C0B0A0908]);
    }

    #[test]
    fn encrypt_kernel_128_28_32() {
        let rounds = 28;
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let pt = [
            0x0F0E0D0C0B0A09080706050403020100u128,
            0x1F1E1D1C1B1A19181716151413121110,
        ];

        let ct = encrypt(pt, &key, rounds);

        assert_eq!(
            ct,
            [
                0xBAFCA120ADD77ADDCFF4A4210991A5ECu128,
                0x40B480E17F4B91FE682D75CDA7C78E06
            ]
        );

        let pt = decrypt(ct, &key, rounds);

        assert_eq!(
            pt,
            [
                0x0F0E0D0C0B0A09080706050403020100u128,
                0x1F1E1D1C1B1A19181716151413121110,
            ]
        );
    }
}
