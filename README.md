
NOTES
### Nonce
 is an arbitrary number that can be used just once in a cryptographic communication.
[1] It is often a random or pseudo-random number issued in an authentication protocol to ensure that old communications cannot be reused in replay attacks.
https://en.wikipedia.org/wiki/Cryptographic_nonce

IV - https://en.wikipedia.org/wiki/Initialization_vector

### LINKS
> https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

> https://github.com/RustCrypto/password-hashes

> https://docs.rs/argon2/latest/argon2/

bcrypt sample:
   https://github.com/DaGenix/rust-crypto/blob/master/src/bcrypt_pbkdf.rs#L271

Rust docs sample: https://rust-lang-nursery.github.io/rust-cookbook/cryptography/encryption.html

---

### other 3rd party libs
https://github.com/rust-unofficial/awesome-rust#cryptography
https://github.com/discord/itsdangerous-rs
Encription (2 way) vs hashing (one way)
	https://stackoverflow.com/questions/326699/difference-between-hashing-a-password-and-encrypting-it
*/
