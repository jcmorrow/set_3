#[macro_use]
extern crate lazy_static;
extern crate openssl;

use openssl::symm::{encrypt, Cipher, Crypter, Mode};
use rand::Rng;
use std::io::Read;

lazy_static! {
    static ref SECRET_KEY: Vec<u8> = random_aes_key();
}

const POSSIBLE_TEXTS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];


pub fn decrypt_block(block: &[u8]) -> Vec<u8> {
    let blocksize = 16;

    // It's helpful to have things split out for reasoning, but it's ok to
    // combine them when what we really want to do is feed them in together as a
    // single cyphertext
    let mut both = vec![0x00; 16];
    both.extend(block.to_vec());

    // This is a plaintext block that starts as all 0s. The last 16 of it should
    // never be touched, which makes our indices get a little confusing.
    //
    // The way to think of it is that whatever we have to XOR char 15 with to
    // get correct padding is actually what char at index 31 is in plaintext.
    // We're *always* decrypting the second block here, so even though we'll
    // return indices 0-15 of `plaintext` those actually represent the plaintext
    // of the block that we're decrypting (indices 15-31 of `both`)
    let mut plaintext = vec![0x00; blocksize * 2];
    for i in (0..16).rev() {
        // The first time through our padding will be
        // 00000000000000010000000000000000
        // The second time
        // 00000000000000220000000000000000
        // The third time
        // 00000000000003330000000000000000
        // Etc., etc.
        let padding = combine_blocks(vec![
            pad_pkcs_7(&(0..i).map(|_| 0x00 as u8).collect::<Vec<u8>>()),
            vec![0; 16],
        ]);
        let masked = xor(&xor(&both, &padding), &plaintext);
        for j in 0..255 {
            let byte = j;

            let first = &masked.to_vec()[0..i];
            let last = &masked.to_vec()[i + 1..blocksize * 2];
            let mut spliced: Vec<u8> = Vec::new();
            spliced.extend_from_slice(&first);
            spliced.push(byte);
            spliced.extend_from_slice(&last);

            if valid_padding_oracle(&spliced) {
                plaintext[i] = byte ^ (blocksize - i) as u8;
            }
        }
    }
    plaintext.iter().take(16).cloned().collect::<Vec<u8>>()
}

pub fn pad_pkcs_7(input: &[u8]) -> Vec<u8> {
    let blocksize = 16;
    let mut destructable = input.to_vec();
    let padding_len = blocksize - destructable.len() % blocksize;

    for _ in 0..padding_len {
        destructable.push(padding_len as u8);
    }
    destructable
}

pub fn valid_pkcs_7_padding(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut destructable = input.to_vec();
    let padding_len = match destructable.pop() {
        Some(0) => return Result::Err("Invalid padding"),
        None => return Result::Err("No content"),
        Some(x) => x,
    };
    let mut found = 1;
    while found < padding_len {
        match destructable.pop() {
            Some(padding) => {
                if padding_len == padding {
                    found += 1;
                } else {
                    return Result::Err("Invalid padding");
                }
            }
            None => return Result::Err("Invalid padding"),
        }
    }
    Result::Ok(destructable)
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|x| x.0 ^ x.1).collect()
}

pub fn encrypt_aes_128_cbc(plaintext: &[u8], key: &str) -> Vec<u8> {
    let blocksize = 16;
    let blocks = plaintext.chunks(blocksize);
    let mut encrypted: Vec<u8> = Vec::new();
    let mut previous_ciphertext_block: Vec<u8> = (0..blocksize).map(|_| 0).collect();
    for block in blocks {
        let xored = &xor(&block, &previous_ciphertext_block);
        let mut text = [0; 16];
        encrypt_aes_128_ecb(xored, key)
            .take(blocksize as u64)
            .read_exact(&mut text)
            .unwrap();
        previous_ciphertext_block = text.to_vec();
        encrypted.append(&mut text.to_vec());
    }
    encrypted
}

pub fn encrypt_aes_128_ecb(decrypted: &[u8], key: &str) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    encrypt(cipher, key.as_bytes(), None, decrypted).unwrap()
}

pub fn oracle(_input: &[u8]) -> Vec<u8> {
    let to_encrypt = hex_to_string(&base_64_to_hex(
        POSSIBLE_TEXTS[rand::thread_rng().gen_range(0, 10)],
    ));

    encrypt_aes_128_cbc(
        &pad_pkcs_7(&to_encrypt.as_bytes()),
        &bytes_to_string(&SECRET_KEY),
    )
}

pub fn valid_padding_oracle(cyphertext: &[u8]) -> bool {
    valid_pkcs_7_padding(&decrypt_aes_128_cbc(
        cyphertext,
        &bytes_to_string(&SECRET_KEY),
    ))
    .is_ok()
}
pub fn decrypt_aes_128_cbc(encrypted: &[u8], key: &str) -> Vec<u8> {
    let blocksize = 16;
    let mut plain: Vec<u8> = Vec::new();

    let blocks: Vec<&[u8]> = encrypted.chunks(blocksize).rev().collect();
    for (i, block) in blocks.clone().iter().enumerate() {
        let previous_cyphertext = match blocks.get(i + 1) {
            Some(x) => x,
            None => &[0 as u8; 16][..],
        };
        let decrypted_block = decrypt_one_block_aes_128_ecb(&block, key.as_bytes());
        let plain_block = xor(&decrypted_block, previous_cyphertext);
        plain.splice(0..0, plain_block.iter().cloned());
    }
    plain
}

pub fn decrypt_one_block_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let mut decrypted = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    let mut output = vec![0 as u8; data.len() + Cipher::aes_128_cbc().block_size()];

    let decrypted_result = decrypted.update(&data, &mut output);

    match decrypted_result {
        Ok(_) => output[0..16].to_owned(),
        Err(e) => panic!("Error decrypting text: {}", e),
    }
}

pub fn random_aes_key() -> Vec<u8> {
    (0..16).map(|_| random_utf8_byte()).collect()
}

pub fn random_utf8_byte() -> u8 {
    rand::thread_rng().gen_range(0, 128)
}

pub fn bytes_to_string(s: &[u8]) -> String {
    String::from_utf8(s.to_owned())
        .unwrap_or_else(|_| panic!("Can't turn {:?} into valid string", s))
}

pub fn base_64_to_hex(s: &str) -> String {
    let mut hex = String::new();
    let mut bins: Vec<u8> = Vec::new();

    for c in s.as_bytes() {
        let index = base_64_index(*c as char);
        if index > -1 {
            bins.append(&mut byte_to_binary(index as u8, 6));
        }
    }

    for c in bins.chunks(8) {
        hex.push_str(&byte_to_hex(binary_to_byte(c)));
    }

    hex
}

pub fn byte_to_hex(b: u8) -> String {
    format!("{:0>2x}", b)
}

pub fn binary_to_byte(bs: &[u8]) -> u8 {
    let mut n: u8 = 0;

    for (i, b) in bs.iter().rev().enumerate() {
        n += (2 as u8).pow(i as u32) * b;
    }

    n
}

pub fn hex_to_string(hex: &str) -> String {
    String::from_utf8(hex_to_bytes(hex))
        .expect("Non UTF-8 byte encounted while converting hex to UTF-8")
}
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks(2).map(hex_to_byte).collect()
}

pub fn hex_to_byte(hex: &[u8]) -> u8 {
    if let Ok(base_16) = String::from_utf8(hex.to_vec()) {
        u32::from_str_radix(&base_16, 16).unwrap() as u8
    } else {
        panic!("Could not parse {:?} as base-16", hex);
    }
}

pub fn base_64_index(c: char) -> isize {
    for (i, ch) in BASE_64_ALPHABET.iter().enumerate() {
        if *ch == c {
            return i as isize;
        }
    }
    -1
}

const BASE_64_ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

pub fn byte_to_binary(c: u8, bits: usize) -> Vec<u8> {
    let mut xs: Vec<u8> = Vec::new();
    let mut quotient: u8 = c as u8;
    let mut remainder: u8;

    while quotient > 0 {
        remainder = quotient % 2;
        quotient /= 2;
        xs.push(remainder);
    }

    xs = pad_with_null_bytes(&xs, bits);
    xs.reverse();
    xs
}

pub fn pad_with_null_bytes(xs: &[u8], len: usize) -> Vec<u8> {
    let mut xs = xs.to_vec();
    while xs.len() < len {
        xs.push(0);
    }
    xs
}

pub fn bytes_to_hex_string(xs: &[u8]) -> String {
    xs.iter().map(|x| byte_to_hex(*x)).collect()
}

pub fn combine_blocks(blocks: Vec<Vec<u8>>) -> Vec<u8> {
    blocks.iter().fold(Vec::new(), |mut acc, ele| {
        acc.extend(ele.clone());
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_blocks() {
        let a: Vec<u8> = (0..16).map(|_| 0x01).collect();
        let b: Vec<u8> = (0..16).map(|_| 0x01).collect();

        let combined: Vec<u8> = (0..32).map(|_| 0x01).collect();
        assert_eq!(combine_blocks(vec![a, b]), combined);
    }
}
