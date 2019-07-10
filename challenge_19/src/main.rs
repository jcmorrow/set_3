// Break fixed-nonce CTR mode using substitutions

// Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate
// a random AES key.

// In successive encryptions (not in one big running CTR stream), encrypt each
// line of the base64 decodes of the following, producing multiple independent
// ciphertexts:

// ...

// (This should produce 40 short CTR-encrypted ciphertexts).

// Because the CTR nonce wasn't randomized for each encryption, each ciphertext
// has been encrypted against the same keystream. This is very bad.

// Understanding that, like most stream ciphers (including RC4, and obviously
// any block cipher run in CTR mode), the actual "encryption" of a byte of data
// boils down to a single XOR operation, it should be plain that:

// CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

// And since the keystream is the same for every ciphertext:

// CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't say!")

// Attack this cryptosystem piecemeal: guess letters, use expected English
// language frequence to validate guesses, catch common English trigrams, and so
// on. Don't overthink it. Points for automating this, but part of the reason
// I'm having you do this is that I think this approach is suboptimal.

extern crate challenge_17;

use challenge_17::*;
use std::cmp;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() {
    let file = File::open("encrypted.txt").unwrap();
    let buf = BufReader::new(file);
    let encrypted_texts = buf
        .lines()
        .map(|x| {
            hex_to_string(&base_64_to_hex(&x.unwrap()))
                .as_bytes()
                .to_vec()
        })
        .collect::<Vec<Vec<u8>>>();

    let longest = encrypted_texts
        .iter()
        .map(std::vec::Vec::len)
        .fold(0, cmp::max);
    let text_columns = (0..longest).map(|position| {
        encrypted_texts.iter().fold(Vec::new(), |mut acc, text| {
            if let Some(c) = text.get(position) {
                acc.push(*c);
            }
            acc
        })
    });
    // OK, so all of this stuff was encrypted with the same nonce, which means
    // the same keystream. We can't get the actual key or nonce back, but we can
    // get the keystream, which allows us to decrypt everything, probably.

    // So, the most basic way to do this is to look at each byte in succession.
    // There won't be *that* many bytes of the keystream that give us reasonable
    // ascii back for each text, so we should be able to find it just by ruling
    // out obvious bad entries.
    let mut keystream: Vec<u8> = Vec::new();
    for column in text_columns {
        let (_decrypted, _score, byte) = decrypt_single_byte_xor(&bytes_to_string(&column));
        keystream.push(byte);
    }
    for text in encrypted_texts {
        dbg!(&bytes_to_string(&xor(&keystream, &text)));
    }
}

pub fn decrypt_single_byte_xor(encrypted: &str) -> (String, f32, u8) {
    let mut decrypted = String::new();
    let mut best_score = 0.0;
    let mut key: u8 = 0;
    for candidate_key in 0..127 {
        let mask_bytes = vec![candidate_key; encrypted.len()];
        let decrypted_bytes = xor(&encrypted.as_bytes(), &mask_bytes);
        let decrypted_plain = bytes_to_string(&decrypted_bytes);
        let score = english_score(&decrypted_plain);
        if score > best_score {
            best_score = score;
            decrypted = decrypted_plain;
            key = candidate_key;
        }
    }
    (decrypted, best_score, key)
}

pub fn bytes_to_string(s: &[u8]) -> String {
    String::from_utf8(s.to_vec()).unwrap_or_else(|_| panic!("Can't turn {:?} into valid string", s))
}

pub fn hex_to_string(hex: &str) -> String {
    String::from_utf8(hex_to_bytes(hex))
        .expect("Non UTF-8 byte encounted while converting hex to UTF-8")
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks(2).map(hex_to_byte).collect()
}

// MSE vs. english frequencies
pub fn english_score(string: &str) -> f32 {
    let error: u32 = character_frequencies(string.as_bytes())
        .iter()
        .zip(character_frequencies(WIKIPEDIA.as_bytes()).iter())
        .map(|x| mse(*x.0, *x.1 as u32))
        .sum();
    10000.0 / error as f32
}

const WIKIPEDIA: &str = "In computing, plain text is a loose term for data (e.g. file contents) that represent only characters of readable material but not its graphical representation nor other objects (floating-point numbers, images, etc.). It may also include a limited number of characters that control simple arrangement of text, such as spaces, line breaks, or tabulation characters (although tab characters can \"mean\" many different things, so are hardly \"plain\"). Plain text is different from formatted text, where style information is included; from structured text, where structural parts of the document such as paragraphs, sections, and the like are identified); and from binary files in which some portions must be interpreted as binary objects (encoded integers, real numbers, images, etc.).";

pub fn character_frequencies(chars: &[u8]) -> [u32; 255] {
    let mut freq = [0 as u32; 255];
    if chars.is_empty() {
        return freq;
    }
    for ch in chars {
        freq[*ch as usize] += 1;
    }
    let freq_vec: Vec<u32> = freq
        .iter()
        .map(|x| (*x as f32 * 100.0 / chars.len() as f32) as u32)
        .collect();

    freq.copy_from_slice(&freq_vec[..255]);
    freq
}

pub fn hex_xor(s1: &str, s2: &str) -> String {
    bytes_to_hex_string(&xor(&hex_to_bytes(&s1), &hex_to_bytes(&s2)))
}

pub fn string_to_hex(s: &str) -> String {
    s.as_bytes().iter().map(|x| byte_to_hex(*x)).collect()
}

pub fn mse(a: u32, b: u32) -> u32 {
    (a as i32 - b as i32).pow(2) as u32
}
