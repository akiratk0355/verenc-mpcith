/* Hashed Elgamal implementation */
#![allow(dead_code)]
#![allow(non_snake_case)]

use crate::utils::*;

use rand::rngs::OsRng;
// ark
use ark_std::{Zero, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_ff::{PrimeField, BigInteger};
use ark_ec::{AffineRepr, Group, CurveGroup};
use ark_secp256r1::{Affine as GGA, Projective as GG};
use ark_secp256r1::Fr as FF;
use ark_ec::scalar_mul::fixed_base::FixedBase;


const WINDOW_SIZE : usize = 7;

#[derive(Clone)]
pub struct Elgamal {
    pub(crate) params: CurveParams,
    pub(crate) precomp_G : Vec<Vec<GGA>>
}

#[derive(Copy, Clone, Default, Debug)]
pub struct PKECipherText {
    pub(crate) c1 : GGA,
    pub(crate) c2 : FF,
}

#[derive(Clone)]
pub struct PKEPublicKey {
    pub(crate) ek : GGA,
    pub(crate) precomp_ek : Vec<Vec<GGA>>
}

impl PKECipherText {
    pub fn zero() -> Self {
        PKECipherText {c1: GGA::zero(), c2: FF::zero()}
    }
}

impl PKECipherText {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut c1_bytes = Vec::new();
        self.c1.serialize_compressed(&mut c1_bytes).unwrap();
        let c2_bytes = self.c2.into_bigint().to_bytes_le();
        [c1_bytes, c2_bytes].concat()
    }
}


impl Elgamal {
    pub fn setup(params: &CurveParams) -> Self {
        let scalar_size = FF::MODULUS_BIT_SIZE as usize;
        let precomp_G = FixedBase::get_window_table::<GG>(scalar_size, WINDOW_SIZE, GG::generator());
        
        Elgamal { params: params.clone(), precomp_G}
    }

    pub fn kgen(&self) -> (PKEPublicKey, FF) {
        let x = FF::rand(&mut OsRng);
        let Y = self.mul_G(x);

        let scalar_size = FF::MODULUS_BIT_SIZE as usize;
        let precomp_ek = FixedBase::get_window_table::<GG>(scalar_size, WINDOW_SIZE, Y.into_group());

        let pk = PKEPublicKey{ek: Y, precomp_ek};
        
        return (pk, x);
    }

    pub fn encrypt(&self, ek: &PKEPublicKey, msg: &FF) -> PKECipherText {
        self.encrypt_given_r(ek, msg, &FF::rand(&mut OsRng))
    }

    fn mul_G(&self, scalar : FF) -> GGA {
        FixedBase::msm::<GG>(FF::MODULUS_BIT_SIZE as usize, WINDOW_SIZE, &self.precomp_G, &[scalar])[0].into_affine()    
    }
    fn mul_ek(precomp_ek : &Vec<Vec<GGA>>, scalar : FF) -> GGA {
        FixedBase::msm::<GG>(FF::MODULUS_BIT_SIZE as usize, WINDOW_SIZE, precomp_ek, &[scalar])[0].into_affine()    
    }

    pub fn encrypt_given_r(&self, ek: &PKEPublicKey, msg: &FF, r: &FF) -> PKECipherText {
        let c1 = self.mul_G(*r);
        self.encrypt_given_c1(ek, msg, r, c1)
    }

    // Encryption where c1 = G^r is given
    pub fn encrypt_given_c1(&self, ek: &PKEPublicKey, msg: &FF, r: &FF, c1 : GGA) -> PKECipherText {
        let keyseed = Self::mul_ek(&ek.precomp_ek, *r);
        let hash = hash_to_FF(&keyseed);
        let c2 = hash + msg;
        PKECipherText { c1, c2 }
    }

    pub fn decrypt(&self, dk: &FF, ct: &PKECipherText) -> FF {
        let pt = (ct.c1 * dk).into_affine();
        let hash = hash_to_FF(&pt);
        ct.c2 - hash
    }

}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pke_kgen() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let (ek, dk) = pke.kgen();
        assert_eq!(params.G * dk, ek.ek);

    }

    #[test]
    fn test_pke_enc_dec() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let (ek, dk) = pke.kgen();
        let m = FF::rand(&mut OsRng);
        let ct = pke.encrypt(&ek, &m);
        let pt = pke.decrypt(&dk, &ct);
        assert_eq!(m, pt);
    }
}