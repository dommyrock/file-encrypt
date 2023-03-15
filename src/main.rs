mod cryptography;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use cryptography::crypto::{decrypt, encrypt};
use rand::rngs::OsRng;
use std::{
    env,
    fs::File,
    io::{Read, Write},
};

fn main() {
    if let (Some(arg1), Some(arg2), Some(arg3)) =
        (env::args().nth(1), env::args().nth(2), env::args().nth(3))
    {
        println!("The first argument is {}", arg1);
        println!("The first argument is {}", arg2);
        println!("The first argument is {}", arg3);
    }

    let pth = env::args().nth(1).expect("1st parameter should be valid .txt file PATH.");
    let out_enc = "encrypted_out.txt";
    let out_dec = "decrypted_out.txt";
    let out_encrypt = format!("<OUT_DIR_PATH>{out_enc}");
    let out_decrypt = format!("<OUT_DIR_PATH>{out_dec}");

    // Open the input and output files
    let mut input_file = File::open(pth).expect("FILE not found at specified location");
    let mut output_file = File::create(out_encrypt).expect("Output location is invalid path");
    let mut output_file2 = File::create(out_decrypt).expect("Output location is invalid path");
    
    // Read the contents of the input file into a buffer
    let mut input_buffer = Vec::new();
    input_file.read_to_end(&mut input_buffer).unwrap();

    //-------------------------ARAGON
    let password = b"hunter42"; // Bad password; don't actually use!
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = Argon2::default()
        .hash_password(password, &salt)
        .unwrap()
        .to_string();

    // Verify password against PHC string.
    //
    // NOTE: hash params from `parsed_hash` are used instead of what is configured in the `Argon2` instance.
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();

    assert!(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok());

    //-------------------------ARAGON
    let mut iv: [u8; 16] = [0; 16];
    let _ = salt.decode_b64(&mut iv);

    /* TO CREATE SALT FROM STRING:
         SaltString::from_b64(salt.to_string().as_str());
         let chrs  = salt.to_string(); //as .chars() if i need them
    */

    let encrypted_data = encrypt(&input_buffer, &parsed_hash.hash.unwrap().as_bytes(), &iv)
        .ok()
        .unwrap();

    let decrypted_data = decrypt(
        &encrypted_data[..],
        &parsed_hash.hash.unwrap().as_bytes(),
        &iv,
    )
    .ok()
    .unwrap();

    //  let mut output_buffer = Vec::new();
    output_file.write_all(&encrypted_data).unwrap();
    output_file2.write_all(&decrypted_data).unwrap();
}
//check equality in UTests
//  let compare_are_equal = message.as_bytes() == &decrypted_data[..];
//  print!("Are equal {}", compare_are_equal);
//  assert!(compare_are_equal);

// https://github.com/DaGenix/rust-crypto
// 	https://github.com/RustCrypto/traits
// 	https://github.com/RustCrypto

/*Nonce
a nonce is an arbitrary number that can be used just once in a cryptographic communication.
[1] It is often a random or pseudo-random number issued in an authentication protocol to ensure that old communications cannot be reused in replay attacks.

https://en.wikipedia.org/wiki/Cryptographic_nonce
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
https://github.com/RustCrypto/password-hashes
https://docs.rs/argon2/latest/argon2/
bcrypt sample
   https://github.com/DaGenix/rust-crypto/blob/master/src/bcrypt_pbkdf.rs#L271

Rust docs sample: https://rust-lang-nursery.github.io/rust-cookbook/cryptography/encryption.html

--- --- --- --- --- --- ---
other 3rd party libs
https://github.com/rust-unofficial/awesome-rust#cryptography
https://github.com/discord/itsdangerous-rs

Encription (2 way) vs hashing (one way)
	https://stackoverflow.com/questions/326699/difference-between-hashing-a-password-and-encrypting-it
*/
