// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The xorshift random number generator.

#![doc(html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk.png",
       html_favicon_url = "https://www.rust-lang.org/favicon.ico",
       html_root_url = "https://docs.rs/rand_xorshift/0.3.0")]

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#![no_std]

use core::num::Wrapping as w;
use core::{fmt, mem};
use rand_core::{RngCore, SeedableRng, Error, impls, le};
#[cfg(feature="serde1")] use serde::{Serialize, Deserialize};
use parity_scale_codec::{Decode, Encode, Input, Error as ParityError};
use sp_std::vec::Vec;

/// An Xorshift random number generator.
///
/// The Xorshift[^1] algorithm is not suitable for cryptographic purposes
/// but is very fast. If you do not know for sure that it fits your
/// requirements, use a more secure one such as `StdRng` or `OsRng`.
///
/// When seeded with zero (i.e. `XorShiftRng::from_seed(0)` is called), this implementation
/// actually uses `0xBAD_5EED_0BAD_5EED_0BAD_5EED_0BAD_5EED` for the seed. This arbitrary value is
/// used because the underlying algorithm can't escape from an all-zero state, and the function is
/// infallible so it can't signal this by returning an error.
///
/// [^1]: Marsaglia, George (July 2003).
///       ["Xorshift RNGs"](https://www.jstatsoft.org/v08/i14/paper).
///       *Journal of Statistical Software*. Vol. 8 (Issue 14).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature="serde1", derive(Serialize,Deserialize))]
pub struct XorShiftRng {
    x: w<u32>,
    y: w<u32>,
    z: w<u32>,
    w: w<u32>,
}

impl Encode for XorShiftRng {
    fn encode(&self) -> Vec<u8>  {
        let mut r = [0u8; mem::size_of::<XorShiftRng>()];
        r[0] = (self.x.0 % 2_i32.pow(8) as u32) as u8;
        r[1] = (self.x.0 / 2_i32.pow(8) as u32) as u8;
        r[2] = (self.x.0 / 2_i32.pow(16) as u32) as u8;
        r[3] = (self.x.0 / 2_i32.pow(24) as u32) as u8;
        r[4] = (self.y.0 % 2_i32.pow(8) as u32) as u8;
        r[5] = (self.y.0 / 2_i32.pow(8) as u32) as u8;
        r[6] = (self.y.0 / 2_i32.pow(16) as u32) as u8;
        r[7] = (self.y.0 / 2_i32.pow(24) as u32) as u8;
        r[8] = (self.z.0 % 2_i32.pow(8) as u32) as u8;
        r[9] = (self.z.0 / 2_i32.pow(8) as u32) as u8;
        r[10] = (self.z.0 / 2_i32.pow(16) as u32) as u8;
        r[11] = (self.z.0 / 2_i32.pow(24) as u32) as u8;
        r[12] = (self.w.0 % 2_i32.pow(8) as u32) as u8;
        r[13] = (self.w.0 / 2_i32.pow(8) as u32) as u8;
        r[14] = (self.w.0 / 2_i32.pow(16) as u32) as u8;
        r[15] = (self.w.0 / 2_i32.pow(24) as u32) as u8;
        r.to_vec()
    }
}

impl Decode for XorShiftRng {
    fn decode<I: Input>(input: &mut I) -> Result<Self, ParityError> {
        let mut buf = [0u8; mem::size_of::<XorShiftRng>()];
		input.read(&mut buf).unwrap();
        let mut xyzw: [u32; 4] = [0; 4];
        for i in 0..xyzw.len() {
            let mut num = 0;
            for k in 0..4 {
                num += buf[(i * 4) + k] as u32 * 2_i32.pow(8 * k as u32) as u32;
            }
            xyzw[i] = num;
        }
        Ok(XorShiftRng {
            x: w(xyzw[0]),
            y: w(xyzw[1]),
            z: w(xyzw[2]),
            w: w(xyzw[3]),
        })
    }
}

// Custom Debug implementation that does not expose the internal state
impl fmt::Debug for XorShiftRng {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "XorShiftRng {{}}")
    }
}

impl RngCore for XorShiftRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let x = self.x;
        let t = x ^ (x << 11);
        self.x = self.y;
        self.y = self.z;
        self.z = self.w;
        let w_ = self.w;
        self.w = w_ ^ (w_ >> 19) ^ (t ^ (t >> 8));
        self.w.0
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for XorShiftRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_u32 = [0u32; 4];
        le::read_u32_into(&seed, &mut seed_u32);

        // Xorshift cannot be seeded with 0 and we cannot return an Error, but
        // also do not wish to panic (because a random seed can legitimately be
        // 0); our only option is therefore to use a preset value.
        if seed_u32.iter().all(|&x| x == 0) {
            seed_u32 = [0xBAD_5EED, 0xBAD_5EED, 0xBAD_5EED, 0xBAD_5EED];
        }

        XorShiftRng {
            x: w(seed_u32[0]),
            y: w(seed_u32[1]),
            z: w(seed_u32[2]),
            w: w(seed_u32[3]),
        }
    }

    fn from_rng<R: RngCore>(mut rng: R) -> Result<Self, Error> {
        let mut b = [0u8; 16];
        loop {
            rng.try_fill_bytes(&mut b[..])?;
            if !b.iter().all(|&x| x == 0) {
                break;
            }
        }

        Ok(XorShiftRng {
            x: w(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            y: w(u32::from_le_bytes([b[4], b[5], b[6], b[7]])),
            z: w(u32::from_le_bytes([b[8], b[9], b[10], b[11]])),
            w: w(u32::from_le_bytes([b[12], b[13], b[14], b[15]])),
        })
    }
}
