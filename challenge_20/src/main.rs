mod mersenne_twister;
use mersenne_twister::MersenneTwister;

fn main() {
    let mut rand = MersenneTwister::new();
    rand.seed(5489);
    for i in 0..624 {
        dbg!(format!("{:0>2x}", rand.extract_number()));
    }
}
