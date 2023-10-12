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
use ark_poly::{Polynomial, DenseUVPolynomial};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_ec::{AffineRepr, Group, CurveGroup, VariableBaseMSM};
use ark_secp256r1::{Affine as GGA, Projective as GG};
use ark_secp256r1::Fr as FF;
use ark_ec::scalar_mul::fixed_base::FixedBase;

pub const RVE_PARAMS : [(usize, usize, usize); 6] = [(132, 64, 67), (192, 36, 145), (512, 23, 406), (160, 80, 55), (256, 226, 30),(704, 684, 20)];  
// (N,t,n) = (2304, 2244, 15) has short ciphertexts, but is too slow.

pub const WINDOW_SIZE : usize = 7;
pub const FIELD_ELT_BYTES : usize = ((FF::MODULUS_BIT_SIZE + 7) / 8) as usize;

#[derive(Clone)]
pub struct RDkgithParams {
    pub N: usize,        // number of parties
    pub t: usize,      // number of parallel repetitions
    pub n: usize,      // size of random subset
}

#[derive(Clone, Debug)]
pub struct RDkgithProof {
    pub(crate) challenge : Vec<u8>,
    pub(crate) polycom: Vec<GGA>, //  A_1,..., A_t
    pub(crate) ctexts : Vec<(PKECipherText, usize)>, // unopened ciphertexts ct_i
    //pub(crate) shares: Vec<Vec<FF>>, // opened (s_i)_{i\in I}
    //pub(crate) rands: Vec<Vec<FF>>, // opened (r_i)_{i\in I}
    pub(crate) shares_rands: Vec<(FF, FF, usize)>,
}

#[derive(Clone, Debug)]
pub struct RDkgithCipherText {
    pub(crate) ctexts : Vec<PKECipherText>,
    pub(crate) aux: Vec<FF>
}

#[derive(Clone)]
pub struct RDkgith {
    pub(crate) params: CurveParams,
    pub(crate) vparams: RDkgithParams,
    pub(crate) pke: Elgamal,
    pub(crate) ek: PKEPublicKey,
    pub(crate) precomp_G : Vec<Vec<GGA>>
}

impl RDkgith {
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

impl VerEnc for RDkgith {
    type SystemParams = CurveParams;
    type Statement = GGA;
    type Witness = FF;
    type PKE = Elgamal; 
    type EncKey = PKEPublicKey;
    type DecKey = FF;
    type VEParams = RDkgithParams;
    type VEProof = RDkgithProof;
    type VECipherText = RDkgithCipherText;

    fn setup(params: &CurveParams, vparams: &Self::VEParams, pke: Self::PKE) -> Self {
        let scalar_size = FF::MODULUS_BIT_SIZE as usize;
        let precomp_G = FixedBase::get_window_table::<GG>(scalar_size, WINDOW_SIZE, GG::generator());
        RDkgith { params: params.clone(), vparams: vparams.clone(), pke, 
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

        
        let mut coeffs = Vec::<FF>::with_capacity(t+1);
        let mut polycom = Vec::<GGA>::with_capacity(t+1);

        let mut ctexts = Vec::<PKECipherText>::with_capacity(N);
        let mut shares = Vec::<FF>::with_capacity(N);
        let mut rands = Vec::<FF>::with_capacity(N);
        let mut ret_ctexts = Vec::<(PKECipherText, usize)>::with_capacity(N-t);
        let mut ret_shares_rands = Vec::<(FF, FF, usize)>::with_capacity(t);

        
        
        /* Sample and commit to polynomial */
        for j in 0..t+1 {
            let aj = 
            if j == 0 {
                wit.clone()
            } else {
                FF::rand(&mut OsRng)
            };
            let Aj = self.mul_G(aj);
            
            coeffs.insert(j, aj);
            polycom.insert(j, Aj);

            // hash
            let mut Aj_bytes = Vec::new();
            Aj.serialize_compressed(&mut Aj_bytes).unwrap();
            hasher.update(Aj_bytes);
        }

        let poly = DensePolynomial::from_coefficients_vec(coeffs);

        for i in 0..N {
            let s = poly.evaluate(&FF::from(i as i32 +1));
            let r = FF::rand(&mut OsRng);
            let ct = self.pke.encrypt_given_r(&self.ek, &s, &r);
            shares.insert(i, s);
            rands.insert(i, r);
            ctexts.insert(i, ct);

            // hash
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
            } else {
                ret_shares_rands.push((shares[i], rands[i], i));
            }
        }
        
        RDkgithProof {
            challenge: chal,
            polycom,
            ctexts: ret_ctexts,
            shares_rands: ret_shares_rands
        }
    }
    
    fn verify(&self, stm: &Self::Statement, pi: &Self::VEProof) -> bool {
        let N = self.vparams.N;
        let t = self.vparams.t;
        let mut hasher = Sha512::new();
        

        // index of hidden parties
        let p_indices = self.expand_challenge(&pi.challenge);

        // hash polycom 
        for j in 0..t+1 {
            let Aj = pi.polycom[j];
            let mut Aj_bytes = Vec::new();
            Aj.serialize_compressed(&mut Aj_bytes).unwrap();
            hasher.update(Aj_bytes);
        }

        // check input format
        if pi.ctexts.len() != N-t || pi.shares_rands.len() != t || p_indices.len() != N-t {
            return false;
        }
        // Reconstruct missing ciphertexts
        let mut ctr_hide = 0;
        let mut ctr_open = 0;
        for i in 0..N {
            if p_indices.contains(&i) {
                let (ct, idx) = pi.ctexts[ctr_hide];
                hasher.update(ct.to_bytes());
                if i != idx {
                    return false;
                }
                ctr_hide += 1;
                
            } else {
                let (s, r, idx) = pi.shares_rands[ctr_open];
                let ct = self.pke.encrypt_given_r(&self.ek, &s, &r);
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

        // Check shares -- Direct implementation: requires computing N MSMs each with t+1 terms.
        // Simpler implementation but quite slow. 
        // for (s, _, i) in &pi.shares_rands {
        //     let mut i_powers = Vec::<FF>::with_capacity(t+1);
        //     let mut i_FF = FF::from(*i as i32 + 1);
        //     let mut i_pow = FF::from(1);
        //     for j in 0..t+1 {
        //         i_powers.insert(j, i_pow);
        //         i_pow = i_pow * i_FF;
        //     }

        //     let left = self.mul_G(*s);
        //     let mut right = GG::msm(&pi.polycom, &i_powers).unwrap();
        //     //let right = (right + stm).into_affine();
        //     //println!("{i}");
        //     if left != right {
        //         return false;
        //     }
        // }
        

        // Check shares -- Batched implementation: requires computing 1 MSM with t+1 terms
        // See the "small exponents test" from the paper:
        // Fast batch verification for modular exponentiation and digital signatures. Mihir Bellare, Juan A. Garay & Tal Rabin, EUROCRYPT'98
        // Basically the verifier takes a random linear combination of the LHSs and RHSs
        let mut left_scalar = FF::zero();
        let mut right_scalars = vec![FF::zero(); t+1];

        for (s, _, i) in &pi.shares_rands {
            let random_d = FF::rand(&mut OsRng);
            // Compute scalars for RHS
            let i_FF = FF::from(*i as i32 + 1);
            let mut i_pow = FF::from(1);
            for j in 0..t+1 {
                right_scalars[j] += i_pow * random_d;
                i_pow = i_pow * i_FF;
            }
            left_scalar += s * &random_d;
  
        }
        let left = self.mul_G(left_scalar);
        let right = GG::msm(&pi.polycom, &right_scalars).unwrap();
        if left != right {
            return false;
        }                

        true
    }

    // Lagrange coeff: product delta_i(0) = prod_{j\neq i} j/(j-i)
    // Postprocessed ciphertext for party index i^*: 
    //    c1 = r * G
    //    c2 = delta_{i^*}(0) (H(r * ek) + s_{i^*}) + sum_{i\neq i^*} delta_{i}(0) s_i
    fn compress(&self, _stm: &Self::Statement, pi: &Self::VEProof) -> Self::VECipherText { 
        let N = self.vparams.N;
        let t = self.vparams.t;
        let n = self.vparams.n;
        let mut new_ctexts = Vec::<PKECipherText>::with_capacity(n);
        let mut aux = Vec::<FF>::with_capacity(n);
        let hide_indices = self.expand_challenge(&pi.challenge);
        let mut open_indices = Vec::<usize>::with_capacity(t);

        let mut lagrange = vec![FF::zero(); N];
        for i in 0..N {
            if !hide_indices.contains(&i) {
                open_indices.push(i);
            }
        }
        
        assert_eq!(open_indices.len(), t);
        
        // preprocess lagrange
        for i in open_indices.iter() {
            let i_FF = FF::from(*i as i32 + 1);
            let mut prod = FF::from(1);
            for j in open_indices.iter() {
                if j != i {
                    let j_FF = FF::from(*j as i32 + 1);
                    prod = prod * j_FF / (j_FF - i_FF);
                }
            }
            lagrange[*i] = prod;
        }
        
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
            let c1_new = ct.c1;
            let mut c2_new = ct.c2;
            let i_hide_FF = FF::from(*i_hide as i32 + 1);
            let mut prod = FF::from(1);
            
            // multiply c2 by i_hide's lagrange
            for j in open_indices.iter() {
                if j != i_hide {
                    let j_FF = FF::from(*j as i32  + 1);
                    prod = prod * j_FF / (j_FF - i_hide_FF);
                }
            }
            c2_new = c2_new * prod; 

            // add sum of lagrange * s_i to c2
            let mut ctr_open = 0;
            for i in open_indices.iter() {
                let i_FF = FF::from(*i as i32 + 1);
                let mut delta_i = lagrange[*i];
                delta_i = delta_i * i_hide_FF / (i_hide_FF - i_FF); // update delta_i using i_hide
                let (s,_,_) = pi.shares_rands[ctr_open];
                c2_new = c2_new + delta_i * s;
                ctr_open += 1;
            }

            new_ctexts.push(PKECipherText { c1: c1_new, c2: c2_new });
            aux.push(prod);

            ctr_hide += 1;

        }

        RDkgithCipherText {
            ctexts: new_ctexts,
            aux // TODO: maybe receiver can recompute this from party indices
        }
    }

    fn recover(&self, stm: &Self::Statement, dk: &Self::DecKey, ve_ct: &Self::VECipherText) -> Self::Witness {
        let n = self.vparams.n;
        for i in 0..n {
            let ct = ve_ct.ctexts[i];
            let delta = ve_ct.aux[i];
            let pt = (ct.c1 * dk).into_affine();
            let hash = hash_to_FF(&pt);
            let ptext = ct.c2 - hash * delta;
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
        let vparams = RDkgithParams{ N: 8, t: 4, n: 4};
        let mut ve = RDkgith::setup(&params, &vparams, pke);
        let dk = ve.kgen();

        assert_eq!(params.G * dk, ve.get_public_key().ek);
        assert_eq!(params.G * dk, ve.get_public_key().ek);
    }

    #[test]
    fn test_ve_igen() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        let vparams = RDkgithParams{ N: 8, t: 4, n: 4};
        let ve = RDkgith::setup(&params, &vparams, pke);
        let (stm, wit) = ve.igen();
        assert_eq!(params.G * wit, stm)
    }

    #[test]
    fn test_ve_prove_verify() {
        let params = CurveParams::init();
        let pke = Elgamal::setup(&params);
        for (N, t, n) in RVE_PARAMS {
        let vparams = RDkgithParams{ N, t, n };
        let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
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
    for (N, t, n) in RVE_PARAMS {
        let vparams = RDkgithParams{ N, t, n };
        let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
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


    pub fn proof_size(pi : &RDkgithProof) -> usize {
        let group_elt_bytes = GGA::compressed_size(&GGA::generator());

        let mut size = pi.challenge.len();
        size += pi.polycom.len() * group_elt_bytes;
        size += pi.ctexts.len() * (pke_ctext_size(&pi.ctexts[0].0) + 8);
        size += pi.shares_rands.len() * (2*FIELD_ELT_BYTES + 8);

        size
    }
    pub fn ctext_size(ctext : &RDkgithCipherText) -> usize {        
        let mut size = ctext.ctexts.len() * pke_ctext_size(&ctext.ctexts[0]);
        size += ctext.aux.len() * FIELD_ELT_BYTES;

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

        for (N, t, n) in RVE_PARAMS {
            let vparams = RDkgithParams{ N, t, n};
            let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
            let dk = ve.kgen();
            let (stm, wit) = ve.igen();
            let pi = ve.prove(&stm, &wit);
            print!("\nN = {}, t = {}, n = {}\n", N, t, n);
            print!("Proof size : {}\n", proof_size(&pi));
            assert!(ve.verify(&stm, &pi));
            let ve_ct = ve.compress(&stm, &pi);
            print!("Ctext size : {}\n", (N-t) * (pke_ctext_size(&ve_ct.ctexts[0]) + FIELD_ELT_BYTES));
            print!("Ctext size (RS): {}\n", ctext_size(&ve_ct));
            let wit_recover = ve.recover(&stm, &dk, &ve_ct);

            assert_eq!(wit_recover, wit);
        }
    }

}
     
