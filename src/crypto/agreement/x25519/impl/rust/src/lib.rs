#![no_std]
#![forbid(unsafe_code)]
#![doc = "Portable research implementation of RFC 7748 X25519."]

use core::hint::black_box;

const MASK: u64 = (1 << 51) - 1;
const BASEPOINT: [u8; 32] = {
    let mut bytes = [0; 32];
    bytes[0] = 9;
    bytes
};

/// The peer input produced the all-zero shared secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPeer;

/// Derive the X25519 public key from 32 private bytes.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    scalar_multiply(private, &BASEPOINT)
}

/// Derive the raw X25519 shared secret, rejecting an all-zero result.
///
/// The calling protocol must authenticate the exchange and apply its KDF.
pub fn shared_secret(private: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], InvalidPeer> {
    let secret = scalar_multiply(private, peer);
    let nonzero = secret
        .iter()
        .fold(0, |accumulator, byte| accumulator | byte);
    if black_box(nonzero) == 0 {
        return Err(InvalidPeer);
    }
    Ok(secret)
}

fn scalar_multiply(private: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let mut scalar = *private;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let x1 = Field::decode(peer);
    let (mut x2, mut z2) = (Field::ONE, Field::ZERO);
    let (mut x3, mut z3) = (x1, Field::ONE);
    let mut swap = 0;

    for position in (0..255).rev() {
        let bit = (scalar[position / 8] >> (position % 8)) & 1;
        Field::swap(swap ^ bit, &mut x2, &mut x3);
        Field::swap(swap ^ bit, &mut z2, &mut z3);
        swap = bit;

        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.scale(121665)));
    }

    Field::swap(swap, &mut x2, &mut x3);
    Field::swap(swap, &mut z2, &mut z3);
    x2.mul(z2.invert()).encode()
}

/// Five reduced radix-2^51 limbs. Products fit in the u128 accumulators.
#[derive(Clone, Copy)]
struct Field([u64; 5]);

impl Field {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    fn decode(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0; 5];
        for (index, &byte) in bytes.iter().enumerate() {
            let byte = u64::from(if index == 31 { byte & 127 } else { byte });
            let offset = index * 8;
            let limb = offset / 51;
            let shift = offset % 51;
            limbs[limb] |= (byte << shift) & MASK;
            if shift > 43 && limb < 4 {
                limbs[limb + 1] |= byte >> (51 - shift);
            }
        }
        Self(limbs)
    }

    fn encode(self) -> [u8; 32] {
        // A carry through all limbs of h + 19 signals h >= 2^255 - 19.
        let mut lower = self.0;
        let mut carry = 19;
        for limb in &mut lower {
            let sum = *limb + carry;
            *limb = sum & MASK;
            carry = sum >> 51;
        }
        let mask = 0u64.wrapping_sub(carry);
        let limbs: [u64; 5] = core::array::from_fn(|i| self.0[i] ^ (mask & (self.0[i] ^ lower[i])));
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 8;
            let limb = offset / 51;
            let shift = offset % 51;
            let mut value = limbs[limb] >> shift;
            if shift > 43 && limb < 4 {
                value |= limbs[limb + 1] << (51 - shift);
            }
            *byte = value as u8;
        }
        bytes
    }

    fn swap(bit: u8, left: &mut Self, right: &mut Self) {
        let mask = 0u64.wrapping_sub(u64::from(bit));
        for i in 0..5 {
            let difference = mask & (left.0[i] ^ right.0[i]);
            left.0[i] ^= difference;
            right.0[i] ^= difference;
        }
    }

    fn reduce(mut limbs: [u128; 5]) -> Self {
        // A carry across bit 255 folds back into limb zero with a factor of 19.
        for _ in 0..3 {
            for i in 0..4 {
                limbs[i + 1] += limbs[i] >> 51;
                limbs[i] &= u128::from(MASK);
            }
            limbs[0] += (limbs[4] >> 51) * 19;
            limbs[4] &= u128::from(MASK);
        }
        Self(limbs.map(|limb| limb as u64))
    }

    fn add(self, other: Self) -> Self {
        Self::reduce(core::array::from_fn(|i| u128::from(self.0[i] + other.0[i])))
    }

    fn sub(self, other: Self) -> Self {
        const TWICE_PRIME: [u64; 5] = [2 * (MASK - 18), 2 * MASK, 2 * MASK, 2 * MASK, 2 * MASK];
        Self::reduce(core::array::from_fn(|i| {
            u128::from(self.0[i] + TWICE_PRIME[i] - other.0[i])
        }))
    }

    fn mul(self, other: Self) -> Self {
        let mut products = [0; 5];
        for i in 0..5 {
            for j in 0..5 {
                let product = u128::from(self.0[i]) * u128::from(other.0[j]);
                if i + j >= 5 {
                    products[i + j - 5] += 19 * product;
                } else {
                    products[i + j] += product;
                }
            }
        }
        Self::reduce(products)
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn scale(self, factor: u64) -> Self {
        Self::reduce(self.0.map(|limb| u128::from(limb) * u128::from(factor)))
    }

    fn square_repeat(self, count: u32) -> Self {
        let mut power = self;
        for _ in 0..count {
            power = power.square();
        }
        power
    }

    fn invert(self) -> Self {
        // z_n denotes self^(2^n - 1). The final exponent is 2^255 - 21.
        let power_2 = self.square();
        let power_9 = power_2.square_repeat(2).mul(self);
        let power_11 = power_9.mul(power_2);
        let z_5 = power_11.square().mul(power_9);
        let z_10 = z_5.square_repeat(5).mul(z_5);
        let z_20 = z_10.square_repeat(10).mul(z_10);
        let z_40 = z_20.square_repeat(20).mul(z_20);
        let z_50 = z_40.square_repeat(10).mul(z_10);
        let z_100 = z_50.square_repeat(50).mul(z_50);
        let z_200 = z_100.square_repeat(100).mul(z_100);
        let z_250 = z_200.square_repeat(50).mul(z_50);
        z_250.square_repeat(5).mul(power_11)
    }
}
