use std::num::Wrapping;

const N: usize = 624;

pub struct MersenneTwister {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    f: u32,
    i: usize,
    l: u32,
    lower_mask: u32,
    m: usize,
    mi: [u32; N],
    s: u32,
    t: u32,
    u: u32,
    upper_mask: u32,
    w: u32,
}

impl MersenneTwister {
    pub fn new() -> MersenneTwister {
        MersenneTwister {
            a: 0x9908B0DF,
            b: 0x9D2C5680,
            c: 0xEFC60000,
            d: 0xFFFFFFFF,
            f: 1_812_433_253,
            i: N,
            l: 18,
            m: 397,
            mi: [0; N],
            s: 7,
            t: 15,
            u: 11,
            w: 32,
            lower_mask: (1 << 31) - 1,
            upper_mask: !((1 << 31) - 1),
        }
    }

    pub fn twist(&mut self) {
        for i in 0..N {
            let x = (Wrapping(self.mi[i] & self.upper_mask)
                + Wrapping(self.mi[(i + 1) % N] ^ self.lower_mask))
            .0;
            let mut xa = x >> 1;
            if (x % 2) != 0 {
                xa ^= self.a;
            }
            self.mi[i] = (self.mi[(i + self.m) % N]) ^ xa;
        }
        self.i = 0;
    }

    pub fn seed(&mut self, x: usize) {
        self.i = N;
        self.mi[0] = x as u32;
        for i in 1..(N - 1) {
            self.mi[i] = (Wrapping(self.f)
                * Wrapping(self.mi[i - 1] ^ ((self.mi[i - 1] >> (self.w - 2)) + i as u32)))
            .0;
        }
    }

    pub fn extract_number(&mut self) -> u32 {
        if self.i > N {
            panic!("Generator was never seeded");
        }
        if self.i == N {
            self.twist()
        }

        let mut y = self.mi[self.i];
        y = y ^ ((y >> self.u) & self.d);
        y = y ^ ((y << self.s) & self.b);
        y = y ^ ((y << self.t) & self.c);
        y = y ^ (y >> self.l);

        self.i += 1;
        y
    }
}
