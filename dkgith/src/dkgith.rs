#![allow(non_snake_case)]

use crate::utils::*;
use crate::pke::*;
use crate::ve::*;
use crate::seed_tree::*;

use core::panic;
use std::convert::TryInto;
use rand::RngCore;
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


const SALT_SIZE : usize = 32;
pub const VE_PARAMS : [(usize, usize, usize); 4] = [(64, 48, 15), (85, 20, 20), (16, 32, 30), (4, 64, 48)];
pub const WINDOW_SIZE : usize = 7;

#[derive(Clone)]
pub struct DkgithParams {
    pub N: usize,        // number of parties
    pub tau: usize,      // number of parallel repetitions
    pub n: usize,        // size of random subset
}

#[derive(Clone, Debug)]
pub struct DkgithProof {
    pub(crate) challenge : Vec<u8>,
    pub(crate) ctexts : Vec<FF>,    // unopened ciphertexts ct_i, only c2 component (c1's recomputed)
    pub(crate) seeds: Vec<Vec<Seed>>, // Seeds required to reconstruct (s_i)_{i\neq i^*}
    pub(crate) deltas : Vec<FF>,
    pub(crate) salt : [u8 ; SALT_SIZE],
}

#[derive(Clone, Debug)]
pub struct DkgithCipherText {
    pub(crate) ctexts : Vec<PKECipherText>,
}

#[derive(Clone)]
pub struct Dkgith {
    pub(crate) params: CurveParams,
    pub(crate) vparams: DkgithParams,
    pub(crate) pke: Elgamal,
    pub(crate) ek: PKEPublicKey,
    pub(crate) precomp_G : Vec<Vec<GGA>>
}

impl Dkgith {
    /* Helper functions not a part of the VerEnc trait */

    pub fn check_instance(&self, stm: &GGA, wit: &FF) -> bool {
        if &(self.params.G * wit).into_affine() == stm {
            return true
        }
        false
    }

    pub fn expand_challenge(&self, challenge: &Vec<u8>) -> Vec<usize> {
        // Computes the index of the unopened party in each of the tau repetitions
        let mut output = Vec::<usize>::new();
        let mut c = challenge.clone();
        while output.len() < self.vparams.tau {

            let ints = bytes_to_u32(&c);
            for i in 0..ints.len() {
                output.push((ints[i] as usize) % self.vparams.N);
                if output.len() == self.vparams.tau {
                    break;
                }
            }

            if output.len() != self.vparams.tau {
                c = hash_SHA512(c.as_slice());
            }
        }
        
        output
    }

    fn ceil_log2(x : usize) -> usize {
        let x_f64 = x as f64;
        x_f64.log2().ceil() as usize
    }

    fn mul_G(&self, scalar : FF) -> GGA {
        FixedBase::msm::<GG>(FF::MODULUS_BIT_SIZE as usize, WINDOW_SIZE, &self.precomp_G, &[scalar])[0].into_affine()    
    }
}

impl VerEnc for Dkgith {
    type SystemParams = CurveParams;
    type Statement = GGA;
    type Witness = FF;
    type PKE = Elgamal; 
    type EncKey = PKEPublicKey;
    type DecKey = FF;
    type VEParams = DkgithParams;
    type VEProof = DkgithProof;
    type VECipherText = DkgithCipherText;

    fn setup(params: &CurveParams, vparams: &Self::VEParams, pke: Self::PKE) -> Self {
        let scalar_size = FF::MODULUS_BIT_SIZE as usize;
        let precomp_G = FixedBase::get_window_table::<GG>(scalar_size, WINDOW_SIZE, GG::generator());
        Dkgith { params: params.clone(), vparams: vparams.clone(), pke, 
            ek : PKEPublicKey { ek: (GGA::zero()), precomp_ek: (vec![vec![GGA::zero(); 0]; 0]) }, 
            precomp_G}
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
        let logN = Self::ceil_log2(N);
        let tau = self.vparams.tau;
        let mut hasher = Sha512::new();

        assert!(N < 65536);     // in various places we assume that (N, tau) are less than 2^16
        assert!(tau < 65536);

        let mut ret_bcasts = Vec::<GGA>::with_capacity(tau);
        let mut ret_ctexts = Vec::<FF>::with_capacity(tau);
        let mut ret_seeds = Vec::<Vec<Seed>>::with_capacity(tau);
        let mut ret_rands = vec![vec![FF::zero(); N]; tau];

        let mut bcasts = vec![vec![GGA::zero(); N]; tau];
        let mut ctexts = vec![vec![PKECipherText::default(); N]; tau];
        let mut shares = vec![vec![FF::zero(); N]; tau];
        let mut rands = vec![vec![FF::zero(); N]; tau];

        let mut root_seeds = Vec::<Seed>::with_capacity(tau);
        let mut seed_trees = Vec::<SeedTree>::with_capacity(tau);
        let mut deltas = Vec::<FF>::with_capacity(tau);

        
        let mut salt = vec![0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        for j in 0..tau {
            root_seeds.push(SeedTree::random_seed()); 
            seed_trees.push(SeedTree::create(&root_seeds[j], logN, &salt, j));

            // Adjust first party's share
            let mut sum = FF::zero();
            for i in 0..N {
                shares[j][i] = seed_to_FF(seed_trees[j].get_leaf(i), &salt.as_slice(), j, i, None);
                sum += &shares[j][i];
            }
            deltas.push(wit - &sum);
            shares[j][0] += deltas[j];

            /* Commit and Hash */            
            for i in 0..N {
                let Yi = self.mul_G(shares[j][i]);
                
                let mut Yi_bytes = Vec::new();
                Yi.serialize_compressed(&mut Yi_bytes).unwrap();
                hasher.update(Yi_bytes);
                bcasts[j][i] = Yi.clone();
                
                let ct = self.pke.encrypt_given_c1(&self.ek, &shares[j][i], &shares[j][i], Yi);
                ctexts[j][i] = ct;

                hasher.update(ct.to_bytes());
            
            }
        } // end parallel repetitions

        // Hash stm and ek
        let mut stm_bytes = Vec::new();
        let mut ek_bytes = Vec::new();
        stm.serialize_compressed(&mut stm_bytes).unwrap();
        hasher.update(stm_bytes);
        self.ek.ek.serialize_compressed(&mut ek_bytes).unwrap();
        hasher.update(ek_bytes);

        let chal = hasher.finalize().to_vec();
        let p_indices = self.expand_challenge(&chal);
        debug_assert!(chal.len() >= tau, "challenge hash is too short!");

        // construct proof
        for j in 0..tau {
            let i_hidden = p_indices[j]; 
            ret_bcasts.insert(j, bcasts[j][i_hidden]);
            ret_ctexts.insert(j, ctexts[j][i_hidden].c2);
            shares[j][i_hidden] = FF::zero();
            rands[j][i_hidden] = FF::zero();
            ret_seeds.push(seed_trees[j].open_seeds(i_hidden));
            ret_rands[j] = rands[j].clone();
            
        }
        
        DkgithProof{
            challenge: chal,
            ctexts: ret_ctexts, 
            seeds: ret_seeds, 
            deltas: deltas,
            salt: salt[0..SALT_SIZE].try_into().unwrap()
        }
    }
    
    fn verify(&self, stm: &Self::Statement, pi: &Self::VEProof) -> bool {
        let N = self.vparams.N;     
        let tau = self.vparams.tau;
        let mut hasher = Sha512::new();
        let p_indices = self.expand_challenge(&pi.challenge);
        let mut shares = vec![vec![FF::zero(); N]; tau];        
        let mut seed_trees = Vec::<SeedTree>::with_capacity(tau);            

        assert!(N < 65536);     // in various places we assume that (N, tau) are less than 2^16
        assert!(tau < 65536);

        for j in 0..tau {
            /* Commit and Hash */            
            let mut Y = GG::zero();
            let i_hidden = p_indices[j];
            if pi.seeds[j].len() != Self::ceil_log2(N) {
                return false;
            }
            seed_trees.push(SeedTree::reconstruct_tree(Self::ceil_log2(N), &pi.salt, j, i_hidden, &pi.seeds[j]));

            // Recompute seeds and Yi's of opened parties
            let mut Ys = vec![GG::zero(); N];
            for i in 0..N {
                shares[j][i] = seed_to_FF(seed_trees[j].get_leaf(i), &pi.salt, j, i, None); 

                if i == 0 {
                    shares[j][i] += pi.deltas[j];
                }
                
                if i != i_hidden {
                   Ys[i] = self.mul_G(shares[j][i]).into_group();
                   Y += Ys[i];
                }
            }
            Ys[i_hidden] = *stm - Y.into_affine();

            // Now hash all shares and commitments/ctexts; note that this indirectly verifies that sum(Ys) = stm
            for i in 0..N {                
                let mut Yi_bytes = Vec::new();
                Ys[i].serialize_compressed(&mut Yi_bytes).unwrap();
                hasher.update(Yi_bytes);
                
                let ct = 
                if i == i_hidden {
                    PKECipherText{c1 : Ys[i].into_affine(), c2 : pi.ctexts[j]}
                } else {
                    self.pke.encrypt_given_c1(&self.ek, &shares[j][i], &shares[j][i], Ys[i].into_affine())
                };
                hasher.update(ct.to_bytes());
            }
        } // end parallel repetitions

        // Hash stm and ek
        let mut stm_bytes = Vec::new();
        let mut ek_bytes = Vec::new();
        stm.serialize_compressed(&mut stm_bytes).unwrap();
        hasher.update(stm_bytes);
        self.ek.ek.serialize_compressed(&mut ek_bytes).unwrap();
        hasher.update(ek_bytes);

        let chal_rec = hasher.finalize().to_vec();
        if chal_rec != pi.challenge {
            return false;
        }

        true
    }
    
    fn compress(&self, stm: &Self::Statement, pi: &Self::VEProof) -> Self::VECipherText { 
        let N = self.vparams.N;
        let tau = self.vparams.tau;
        let n = self.vparams.n;
        let mut new_ctexts = Vec::<PKECipherText>::with_capacity(n);
        let p_indices = self.expand_challenge(&pi.challenge);
        let T: Vec<usize> = (0..tau).collect();

        // sample random subset of size n
        let subset = T.iter().choose_multiple(&mut OsRng, n);

        for j_ref in subset {
            let j = *j_ref;
            let mut c2_new = pi.ctexts[j];
            let mut sum = FF::zero();
            let i_hidden = p_indices[j];
            assert!(pi.seeds[j].len() == Self::ceil_log2(N));    // already ensured by Verify()

            let seed_tree = SeedTree::reconstruct_tree(Self::ceil_log2(N), &pi.salt, j, i_hidden, &pi.seeds[j]);

            for i in 0..N {
                if i == i_hidden {
                    continue
                }
                let seed = seed_tree.get_leaf(i);
                let mut share = seed_to_FF(seed, &pi.salt, j, i, None);
                if i == 0 {
                    share += pi.deltas[j];
                }
                sum += share;
            }
            let c1_new = *stm - self.mul_G(sum);
            c2_new = c2_new + sum;
            new_ctexts.push(PKECipherText { c1: c1_new.into_affine(), c2: c2_new });
        }

        DkgithCipherText {
            ctexts: new_ctexts
        }
    }

    fn recover(&self, stm: &Self::Statement, dk: &Self::DecKey, ve_ct: &Self::VECipherText) -> Self::Witness {
        let n = self.vparams.n;
        
        for j in 0..n {
            let ct = ve_ct.ctexts[j];
            let ptext = self.pke.decrypt(dk, &ct);
            if self.check_instance(stm, &ptext) {
                return ptext;
            }
        }
        print!("recover: recovery failed!\n");
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
        let vparams = DkgithParams{ N: 4, tau: 4, n: 4};
        let mut ve = Dkgith::setup(&params, &vparams, pke);
        let dk = ve.kgen();

        assert_eq!(params.G * dk, ve.get_public_key().ek);
        assert_eq!(params.G * dk, ve.get_public_key().ek);
    }

    #[test]
    fn test_ve_igen() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let vparams = DkgithParams{ N: 4, tau: 4, n: 4};
        let ve = Dkgith::setup(&params, &vparams, pke);
        let (stm, wit) = ve.igen();
        assert_eq!(params.G * wit, stm)
    }

    #[test]
    fn test_ve_prove_verify() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        for (N, tau, n) in VE_PARAMS {
            let vparams = DkgithParams{ N, tau, n};
            let mut ve = Dkgith::setup(&params, &vparams, pke.clone());
            let _dk = ve.kgen();
            let (stm, wit) = ve.igen();
            let pi = ve.prove(&stm, &wit);
            println!("proof generated");
            let result = ve.verify(&stm, &pi);
            assert!(result);
        }
    }

    #[test]
    fn test_ve_faulty_prove_verify() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let N = 4;
        let tau = 4;
        let n = 4;
        let vparams = DkgithParams{ N, tau, n};
        let mut ve = Dkgith::setup(&params, &vparams, pke);
        let _dk = ve.kgen();
        let (stm, wit) = ve.igen();
        let mut pi = ve.prove(&stm, &wit);
        println!("proof generated");
        // poisoning the proof string
        for j in 0..tau {
            pi.seeds[j][0] = SeedTree::zero_seed();
        }
        let result = ve.verify(&stm, &pi);
        assert!(!result);
    }

    #[test]
    fn test_ve_prove_compress_recover() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);

        for (N, tau, n) in VE_PARAMS {
            let vparams = DkgithParams{ N, tau, n};
            let mut ve = Dkgith::setup(&params, &vparams, pke.clone());
            let dk = ve.kgen();
            let (stm, wit) = ve.igen();
            let pi = ve.prove(&stm, &wit);
            println!("proof generated");
            assert!(ve.verify(&stm, &pi));
            let ve_ct = ve.compress(&stm, &pi);
            println!("VE ciphertext generated");
            let wit_recover = ve.recover(&stm, &dk, &ve_ct);

            assert_eq!(wit_recover, wit);
        }
    }

    #[test]
    fn test_ve_faulty_prove_compress_recover() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let N = 16;
        let tau = 16;
        let n = 12;
        let vparams = DkgithParams{ N, tau, n};
        let mut ve = Dkgith::setup(&params, &vparams, pke);
        let dk = ve.kgen();
        let (stm, wit) = ve.igen();
        let mut pi = ve.prove(&stm, &wit);
        assert!(ve.verify(&stm, &pi));
        println!("proof generated");
        // poisoning the proof string
        for j in 0..tau/2 {
            pi.ctexts[j] += FF::from(1);
        }
        assert!(!ve.verify(&stm, &pi));
        let ve_ct = ve.compress(&stm, &pi);
        println!("VE ciphertext generated");
        let wit_recover = ve.recover(&stm, &dk, &ve_ct);

        assert_eq!(wit_recover, wit);
    }

    pub fn proof_size(pi : &DkgithProof) -> usize {
        let field_elt_bytes = ((FF::MODULUS_BIT_SIZE + 7) / 8) as usize;

        let mut size = pi.challenge.len();
        size += pi.ctexts.len() * field_elt_bytes;      // During proof the ciphertext is only c2
        size += pi.seeds.len() * pi.seeds[0].len() * SEED_BYTES;
        size += pi.deltas.len() * field_elt_bytes;
        size += SALT_SIZE;

        size
    }
    pub fn ctext_size(ctext : &DkgithCipherText) -> usize {
        let group_elt_bytes = GGA::compressed_size(&GGA::generator());
        let field_elt_bytes = ((FF::MODULUS_BIT_SIZE + 7) / 8) as usize;

        let size = ctext.ctexts.len() * (group_elt_bytes + field_elt_bytes);   // The verifier recomputes c1 must include both (c1, c2) here

        size
    }
    pub fn pke_ctext_size(_ctext : &PKECipherText) -> usize {
        let group_elt_bytes = GGA::compressed_size(&GGA::generator());
        let field_elt_bytes = ((FF::MODULUS_BIT_SIZE + 7) / 8) as usize;

        let size = group_elt_bytes + field_elt_bytes;

        size

    }

    #[test]
    fn test_ve_print_sizes() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);

        for (N, tau, n) in VE_PARAMS {
            let vparams = DkgithParams{ N, tau, n};
            let mut ve = Dkgith::setup(&params, &vparams, pke.clone());
            let dk = ve.kgen();
            let (stm, wit) = ve.igen();
            let pi = ve.prove(&stm, &wit);
            print!("\nN = {}, tau = {}, n = {}\n", N, tau, n);
            print!("Proof size : {}\n", proof_size(&pi));
            assert!(ve.verify(&stm, &pi));
            let ve_ct = ve.compress(&stm, &pi);
            print!("Ctext size : {}\n", tau * pke_ctext_size(&ve_ct.ctexts[0]));
            print!("Ctext size (RS): {}\n", ctext_size(&ve_ct));
            let wit_recover = ve.recover(&stm, &dk, &ve_ct);

            assert_eq!(wit_recover, wit);
        }
    }
    
}

