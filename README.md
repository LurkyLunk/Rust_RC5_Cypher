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

