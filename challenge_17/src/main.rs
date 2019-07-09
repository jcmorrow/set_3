extern crate challenge_17;
use challenge_17::*;

fn main() {
    let ciphertext = oracle(b"");
    let mut before = vec![0x00; 16];
    for block in ciphertext.chunks(16) {
        let decrypted = decrypt_block(&block);
        dbg!(bytes_to_string(&xor(&before, &decrypted)));
        before = block.to_vec();
    }
}
