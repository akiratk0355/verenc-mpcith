#![allow(non_snake_case)]

use crate::utils::*;
use crate::pke::*;
use crate::ve::*;

use rand::rngs::OsRng;
use rand::seq::IteratorRandom;
use sha2::{Digest, Sha512};


// ark
use ark_std::{Zero, UniformRand, ops::Mul};
use ark_serialize::CanonicalSerialize;
use ark_ff::{PrimeField};
use ark_ec::{AffineRepr, Group, CurveGroup};
use ark_secp256r1::{Affine as GGA, Projective as GG};
use ark_secp256r1::Fr as FF;
use ark_ec::scalar_mul::fixed_base::FixedBase;

pub const CDVE_PARAMS : [(usize, usize); 3] = [(712, 712-20), (250, 250-30), (132, 132- 64)];  

pub const WINDOW_SIZE : usize = 7;
pub const FIELD_ELT_BYTES : usize = ((FF::MODULUS_BIT_SIZE + 7) / 8) as usize;

#[derive(Clone)]
pub struct CDParams {
    pub N: usize,        // Corresponds to CD00 parameter k
    pub t: usize,        // Corresponds to CD00 parameter k-u
}

#[derive(Clone, Debug)]
pub struct CDProof {
    pub(crate) challenge : Vec<u8>,
    pub(crate) As: Vec<(GGA, usize)>, //  g^r
    pub(crate) ctexts : Vec<(PKECipherText, usize)>, // unopened ciphertexts ct_i
    pub(crate) w0s_rands: Vec<(FF, FF, usize)>,
    pub(crate) w1s: Vec<(FF,usize)>
}

#[derive(Clone, Debug)]
pub struct CDCipherText {
    pub(crate) ctexts : Vec<PKECipherText>,
}

#[derive(Clone)]
pub struct CD {
    pub(crate) params: CurveParams,
    pub(crate) vparams: CDParams,
    pub(crate) pke: Elgamal,
    pub(crate) ek: PKEPublicKey,
    pub(crate) precomp_G : Vec<Vec<GGA>>
}

impl CD {
    pub fn check_instance(&self, stm: &GGA, wit: &FF) -> bool {
        if &(self.params.G * wit).into_affine() == stm {
            return true
        }
        false
    }

    pub fn expand_challenge(&self, challenge: &Vec<u8>) -> Vec<usize> {
        let length_required = self.vparams.N - self.vparams.t;
        let mut output = Vec::<usize>::new();
        let mut c = challenge.clone();
        while output.len() < length_required {

            let ints = bytes_to_u32(&c);
            for i in 0..ints.len() {
                let idx = (ints[i] as usize) % self.vparams.N;
                if !output.contains(&idx) {
                    output.push(idx);
                }
                if output.len() == length_required {
                    break;
                }
            }

            if output.len() != length_required {
                c = hash_SHA512(c.as_slice());
            }
        }
        output.sort();
        output
    }    
    
    fn mul_G(&self, scalar : FF) -> GGA {
        FixedBase::msm::<GG>(FF::MODULUS_BIT_SIZE as usize, WINDOW_SIZE, &self.precomp_G, &[scalar])[0].into_affine()    
    }
}

impl VerEnc for CD {
    type SystemParams = CurveParams;
    type Statement = GGA;
    type Witness = FF;
    type PKE = Elgamal; 
    type EncKey = PKEPublicKey;
    type DecKey = FF;
    type VEParams = CDParams;
    type VEProof = CDProof;
    type VECipherText = CDCipherText;

    fn setup(params: &CurveParams, vparams: &Self::VEParams, pke: Self::PKE) -> Self {
        let scalar_size = FF::MODULUS_BIT_SIZE as usize;
        let precomp_G = FixedBase::get_window_table::<GG>(scalar_size, WINDOW_SIZE, GG::generator());
        CD { params: params.clone(), vparams: vparams.clone(), pke, 
            ek : PKEPublicKey{ek: GGA::zero(), precomp_ek: (vec![vec![GGA::zero(); 0]; 0])},
            precomp_G
        }
    }

    fn kgen(&mut self) -> Self::DecKey {
        let (ek, dk) = self.pke.kgen();
        self.ek = ek;
        return dk;
    }
    
    fn get_public_key(&self) ->  &Self::EncKey {
        &self.ek
    }

    fn igen(&self) -> (Self::Statement, Self::Witness) {
        let x = FF::rand(&mut OsRng);
        let Y = if self.params.G == GGA::generator() {
            self.params.G.mul(x).into_affine()
        } else {
            (self.params.G * x).into_affine()
        };
        return (Y, x);
    }
    
    fn prove(&self, stm: &Self::Statement, wit: &Self::Witness) -> Self::VEProof {
        let N = self.vparams.N;
        let t = self.vparams.t;
        let mut hasher = Sha512::new();

        let mut w0s = Vec::<FF>::with_capacity(N);
        let mut w1s = Vec::<FF>::with_capacity(N);
        let mut As = Vec::<GGA>::with_capacity(N);
        let mut ctexts = Vec::<PKECipherText>::with_capacity(N);
        let mut rands = Vec::<FF>::with_capacity(N);
        
        let mut ret_ctexts = Vec::<(PKECipherText, usize)>::with_capacity(N-t);
        let mut ret_w1s = Vec::<(FF, usize)>::with_capacity(N-t);
        let mut ret_As = Vec::<(GGA, usize)>::with_capacity(N-t);
        let mut ret_w0s_rands = Vec::<(FF, FF, usize)>::with_capacity(t);
        
        
        /* Sample and commit to share */
        for _ in 0..N {
            let w0 = FF::rand(&mut OsRng);
            let w1 = wit - &w0;

            let A = self.mul_G(w0);
            
            let r = FF::rand(&mut OsRng);
            let ct = self.pke.encrypt_given_r(&self.ek, &w0, &r);
            w0s.push(w0);
            w1s.push(w1);
            As.push(A);
            rands.push(r);
            ctexts.push(ct);

            // hash
            let mut A_bytes = Vec::new();
            A.serialize_compressed(&mut A_bytes).unwrap();
            hasher.update(A_bytes);
            hasher.update(ct.to_bytes());
        }

        // Hash stm and ek
        let mut stm_bytes = Vec::new();
        let mut ek_bytes = Vec::new();
        stm.serialize_compressed(&mut stm_bytes).unwrap();
        hasher.update(stm_bytes);
        self.ek.ek.serialize_compressed(&mut ek_bytes).unwrap();
        hasher.update(ek_bytes);

        let chal = hasher.finalize().to_vec();
        let p_indices = self.expand_challenge(&chal);

        // construct proof
        for i in 0..N {
            if p_indices.contains(&i) {
                ret_ctexts.push((ctexts[i], i));
                ret_w1s.push((w1s[i],i));
                ret_As.push((As[i],i));
            } else {
                ret_w0s_rands.push((w0s[i], rands[i], i));
            }
        }
        
        CDProof {
            challenge: chal,
            As: ret_As,
            ctexts: ret_ctexts,
            w0s_rands: ret_w0s_rands,
            w1s: ret_w1s,
        }
    }
    
    fn verify(&self, stm: &Self::Statement, pi: &Self::VEProof) -> bool {
        let N = self.vparams.N;
        let t = self.vparams.t;
        let mut hasher = Sha512::new();
        

        // index of hidden parties
        let p_indices = self.expand_challenge(&pi.challenge);

        // check input format
        if pi.ctexts.len() != N-t || pi.w0s_rands.len() != t || p_indices.len() != N-t {
            return false;
        }
        // Reconstruct missing ciphertexts
        let mut ctr_hide = 0;
        let mut ctr_open = 0;
        for i in 0..N {
            if p_indices.contains(&i) {
                let (A, _) = pi.As[ctr_hide];
                let (w1, _) = pi.w1s[ctr_hide];
                let (ct, idx) = pi.ctexts[ctr_hide];
                let mut A_bytes = Vec::new();
                A.serialize_compressed(&mut A_bytes).unwrap();
                hasher.update(A_bytes);
                hasher.update(ct.to_bytes());
                if i != idx {
                    return false;
                }
                if stm != &(A + self.mul_G(w1)).into_affine() {
                    return false;
                }
                ctr_hide += 1;
                
            } else {
                let (w0, r, idx) = pi.w0s_rands[ctr_open];
                let A = self.mul_G(w0);
                let ct = self.pke.encrypt_given_r(&self.ek, &w0, &r);
                let mut A_bytes = Vec::new();
                A.serialize_compressed(&mut A_bytes).unwrap();
                hasher.update(A_bytes);
                hasher.update(ct.to_bytes());
                if i != idx {
                    return false;
                }
                ctr_open += 1;
            }
        }
        // Hash stm and ek
        let mut stm_bytes = Vec::new();
        let mut ek_bytes = Vec::new();
        stm.serialize_compressed(&mut stm_bytes).unwrap();
        hasher.update(stm_bytes);
        self.ek.ek.serialize_compressed(&mut ek_bytes).unwrap();
        hasher.update(ek_bytes);

        // check hash
        let chal_rec = hasher.finalize().to_vec();
        if chal_rec != pi.challenge {
            return false;
        }     

        true
    }

    // Postprocessed ciphertext for party index i^*: 
    //    c1 = r * G
    //    c2 = H(r * ek) + w0 + w1
    fn compress(&self, _stm: &Self::Statement, pi: &Self::VEProof) -> Self::VECipherText { 
        let N = self.vparams.N;
        let t = self.vparams.t;
        let n = N-t; // fixed
        let mut new_ctexts = Vec::<PKECipherText>::with_capacity(n);
        
        let hide_indices = self.expand_challenge(&pi.challenge);
        let mut open_indices = Vec::<usize>::with_capacity(t);

        for i in 0..N {
            if !hide_indices.contains(&i) {
                open_indices.push(i);
            }
        }
        
        assert_eq!(open_indices.len(), t);
                
        // sample random subset of size n
        let subset= hide_indices.iter().choose_multiple(&mut OsRng, n);

        let mut ctr_hide = 0;
        
        // process each ciphertext
        for i_hide in hide_indices.iter() {
            if !subset.contains(&i_hide) {
                ctr_hide += 1;
                continue;
            }
            
            let (ct, _idx) = pi.ctexts[ctr_hide];
            let (w1, _) = pi.w1s[ctr_hide];
            let c1_new = ct.c1;
            let c2_new = ct.c2 + w1;
            
            new_ctexts.push(PKECipherText { c1: c1_new, c2: c2_new });
            

            ctr_hide += 1;

        }

        CDCipherText {
            ctexts: new_ctexts,
        }
    }

    fn recover(&self, stm: &Self::Statement, dk: &Self::DecKey, ve_ct: &Self::VECipherText) -> Self::Witness {
        let N = self.vparams.N;
        let t = self.vparams.t;
        let n = N-t;
        for i in 0..n {
            let ct = ve_ct.ctexts[i];
            
            let pt = (ct.c1 * dk).into_affine();
            let hash = hash_to_FF(&pt);
            let ptext = ct.c2 - hash;
            if self.check_instance(stm, &ptext) {
                return ptext;
            }
        }
        print!("recovery failed!");
        FF::zero()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ve_kgen() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let vparams = CDParams{ N: 8, t: 4};
        let mut ve = CD::setup(&params, &vparams, pke);
        let dk = ve.kgen();

        assert_eq!(params.G * dk, ve.get_public_key().ek);
        assert_eq!(params.G * dk, ve.get_public_key().ek);
    }

    #[test]
    fn test_ve_igen() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let vparams = CDParams{ N: 8, t: 4};
        let ve = CD::setup(&params, &vparams, pke);
        let (stm, wit) = ve.igen();
        assert_eq!(params.G * wit, stm)
    }

    #[test]
    fn test_ve_prove_verify() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        for (N, t) in CDVE_PARAMS {
        let vparams = CDParams{ N, t };
        let mut ve = CD::setup(&params, &vparams, pke.clone());
        let _dk = ve.kgen();
        let (stm, wit) = ve.igen();
        let pi = ve.prove(&stm, &wit);
        println!("proof generated");
        let result = ve.verify(&stm, &pi);
        println!("proof verified");
        assert!(result);
    }
    }

    #[test]
    fn test_ve_prove_compress_recover() {
    let params = CurveParams::init();
    let pke = Elgamal::setup(&params);
    for (N, t) in CDVE_PARAMS {
        let vparams = CDParams{ N, t };
        let mut ve = CD::setup(&params, &vparams, pke.clone());
        let dk = ve.kgen();
        let (stm, wit) = ve.igen();
        let pi = ve.prove(&stm, &wit);
        println!("proof generated");
        let ve_ct = ve.compress(&stm, &pi);
        println!("VE ciphertext generated");
        let wit_recover = ve.recover(&stm, &dk, &ve_ct);
        assert_eq!(wit_recover, wit);
    }
    }



    pub fn proof_size(pi : &CDProof) -> usize {
        let group_elt_bytes = GGA::compressed_size(&GGA::generator());

        let mut size = pi.challenge.len();
        size += pi.As.len() * (group_elt_bytes + 8);
        size += pi.ctexts.len() * (pke_ctext_size(&pi.ctexts[0].0) + 8);
        size += pi.w0s_rands.len() * (2*FIELD_ELT_BYTES + 8);
        size += pi.w1s.len() * (FIELD_ELT_BYTES + 8);

        size
    }
    pub fn ctext_size(ctext : &CDCipherText) -> usize {        
        let size = ctext.ctexts.len() * pke_ctext_size(&ctext.ctexts[0]);

        size
    }
    pub fn pke_ctext_size(_ctext : &PKECipherText) -> usize {
        let group_elt_bytes = GGA::compressed_size(&GGA::generator());
        let size = group_elt_bytes + FIELD_ELT_BYTES;

        size

    }
     

    #[test]
    fn test_ve_print_sizes() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);

        for (N, t) in CDVE_PARAMS {
            let vparams = CDParams{ N, t};
            let mut ve = CD::setup(&params, &vparams, pke.clone());
            let dk = ve.kgen();
            let (stm, wit) = ve.igen();
            let pi = ve.prove(&stm, &wit);
            print!("\nN = {}, t = {}\n", N, t);
            print!("Proof size : {}\n", proof_size(&pi));
            assert!(ve.verify(&stm, &pi));
            let ve_ct = ve.compress(&stm, &pi);
            print!("Ctext size : {}\n", (N-t) * (pke_ctext_size(&ve_ct.ctexts[0])));
            print!("Ctext size (RS): {}\n", ctext_size(&ve_ct));
            let wit_recover = ve.recover(&stm, &dk, &ve_ct);

            assert_eq!(wit_recover, wit);
        }
    }
    

}
     
