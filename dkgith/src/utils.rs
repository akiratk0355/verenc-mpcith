#![allow(non_snake_case)]

use sha2::{Digest, Sha512};
use crate::Seed;
use std::convert::TryInto;

// ark
use ark_serialize::CanonicalSerialize;
use ark_ff::PrimeField;
use ark_ec::AffineRepr;
use ark_secp256r1::Affine as GGA;
use ark_secp256r1::Fr as FF;


pub type Statement = GGA;
pub type Witness = FF;


#[derive(Clone, Default, PartialEq, Debug)]
pub struct CurveParams {
    pub(crate) G: GGA, // base point
}

impl CurveParams {
    pub fn init() -> Self {
        let G = GGA::generator(); 
       
        CurveParams {
            G
        }
    }
}

/* Utility functions */
pub fn hash_to_FF(point: &GGA) -> FF {
   
    let mut pbt = Vec::new();
    point.serialize_compressed(&mut pbt).unwrap();
    let digest = hash_SHA512(pbt.as_slice());

    FF::from_le_bytes_mod_order(&digest)
}

pub fn hash_SHA512(input : &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(input);
    
    hasher.finalize().to_vec()
}

pub fn bytes_to_u32(input : &Vec<u8>) -> Vec<u32> {
    let extra = input.len() % 4;
    let mut output = Vec::<u32>::new();
    for i in (0..input.len()-extra).step_by(4) {
        let next_bytes : [u8 ; 4] = input[i..i+4].try_into().unwrap();
        output.push(u32::from_le_bytes(next_bytes));
    }
    output
}

// Derive a uniformly random field element from a seed, 
// assuming the bitlength of the field is less than 448 bits
// Used to convert seeds to shares.
pub fn seed_to_FF(seed: Seed, salt: &[u8], rep_index : usize, party_index : usize, additional_input : Option<&[u8]>) -> FF {
    let rep_index = rep_index as u16;
    let party_index = party_index as u16;
    let mut hasher = Sha512::new();
    hasher.update(salt);
    hasher.update(seed);
    hasher.update(rep_index.to_le_bytes());
    hasher.update(party_index.to_le_bytes());
    if additional_input.is_some() {
        hasher.update(additional_input.unwrap());
    }
    
    let digest = hasher.finalize();

    FF::from_le_bytes_mod_order(&digest)
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256r1::Projective as GG;
    use ark_ec::Group;
    use crate::ark_std::UniformRand;
    #[test]
    fn test_ec() {
        let mut rng = ark_std::test_rng();
        let G = GG::generator();
        let x = FF::rand(&mut rng);
        let Y = G * x;
        println!("G = {:?}", G);
        println!("x = {:?}", x);
        println!("Y = {:?}", Y);
    }
    #[test]
    fn test_system() {
        let params = CurveParams::init();
        println!("PARAMS = {:#x?}", params);
    }  
}