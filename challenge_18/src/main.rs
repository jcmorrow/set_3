extern crate challenge_17;

use challenge_17::*;

fn main() {
    let encrypted = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

    // dbg!(bytes_to_string(&encrypt_aes_128_ctr(&hex_to_bytes(&base_64_to_hex(&encrypted)), "YELLOW SUBMARINE",  &vec![0; 8])));
    dbg!(bytes_to_string(&encrypt_aes_128_ctr(
        &hex_to_bytes(&base_64_to_hex(&encrypted)),
        "YELLOW SUBMARINE",
        &vec![0; 8]
    )));
}

pub fn encrypt_aes_128_ctr(plaintext: &[u8], key: &str, nonce: &[u8]) -> Vec<u8> {
    let mut counter_index = 0;
    let mut counter = vec![0; 8];
    let mut encrypted: Vec<u8> = Vec::new();
    for block in plaintext.chunks(16) {
        let mut nonce_and_counter: Vec<u8> = Vec::new();
        nonce_and_counter.extend(nonce);
        nonce_and_counter.extend(counter.clone());
        dbg!(&nonce_and_counter);
        let next_block = xor(&block, &encrypt_aes_128_ecb(&nonce_and_counter, key));
        dbg!(bytes_to_hex_string(&next_block));
        dbg!(&next_block);
        encrypted.extend(next_block);

        if counter[counter_index] == 255 {
            counter_index += 1;
        }
        counter[counter_index] += 1;
    }
    encrypted
}
