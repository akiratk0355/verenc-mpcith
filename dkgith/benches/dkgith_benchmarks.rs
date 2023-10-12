#![allow(non_snake_case)]

use criterion::{criterion_group, criterion_main, Criterion};

extern crate dkgith;
use dkgith::*;
   
// ark
use ark_std::{UniformRand, ops::Mul};
use ark_ff::{PrimeField};
use ark_ec::{AffineRepr, Group, VariableBaseMSM};
use ark_secp256r1::{Affine as GGA, Projective as GG};
use ark_secp256r1::Fr as FF;

// To get proof and ciphertext sizes, see the unit test test_ve_print_sizes for dkgith and rdkgith

// Note: To filter benchmarks with Criterion, the command:
//     cargo bench -- filter_re
// where filter_re is a regular expression that matches the name given to the bench_function() method. 
// For example
//     cargo bench -- "^MUL"
//  for some of scalar mul benchmarks
//     cargo bench -- "^DKGitH"
//     cargo bench -- RDKGitH


fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {

    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();

    coeffs
}

fn benchmark_ecc(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    
    let G = GG::generator();
    let G_a = GGA::generator();
    
    let mut scalars = vec!();
    scalars.push(FF::rand(&mut rng));
    
    let mut points = vec!();
    let mut points_a = vec!();
    points.push(GG::rand(&mut rng));
    points_a.push(GGA::rand(&mut rng));

    c.bench_function("MUL scalar multiplication (projective)", |b| {
        b.iter(|| points[0].mul(&scalars[0]))
    });

    c.bench_function("MUL scalar multiplication (affine)", |b| {
        b.iter(|| points_a[0].mul(&scalars[0]))
    });

    c.bench_function("MUL fixed-base scalar multiplication (projective)", |b| {
        b.iter(|| G.mul(&scalars[0]))
    });

    c.bench_function("MUL fixed-base scalar multiplication (affine)", |b| {
        b.iter(|| G_a.mul(&scalars[0]))
    });

    scalars.push(FF::rand(&mut rng));
    points.push(GG::rand(&mut rng));
    points_a.push(GGA::rand(&mut rng));

    c.bench_function("MUL Pedersen commitment", |b| {
        b.iter(|| GG::msm(points_a.as_slice(), scalars.as_slice()))
    });

    for _ in 0..126 {
        scalars.push(FF::rand(&mut rng));
        points.push(GG::rand(&mut rng));
        points_a.push(GGA::rand(&mut rng));
    }

    c.bench_function("MUL Pedersen vector commitment (with 128 generators) GG::msm", |b| {
        b.iter(|| GG::msm(points_a.as_slice(), scalars.as_slice()))
    });

    c.bench_function("MUL Pedersen vector commitment (with 128 generators) VariableBaseMSM::msm", |b| {
        b.iter(||<GG as VariableBaseMSM>::msm(points_a.as_slice(), scalars.as_slice())   )
    });

    let scalars_bigints = convert_to_bigints(scalars.as_slice());
    c.bench_function("MUL Pedersen vector commitment (with 128 generators) VariableBaseMSM::msm_bigint", |b| {
        b.iter(||<GG as VariableBaseMSM>::msm_bigint(points_a.as_slice(), &scalars_bigints)   )
    });

    for _ in 0..1000 {
        scalars.push(FF::rand(&mut rng));
        points_a.push(GGA::rand(&mut rng));
    }

    c.bench_function("MUL Pedersen vector commitment (with 1128 generators) GG::msm", |b| {
        b.iter(|| GG::msm(points_a.as_slice(), scalars.as_slice()))
    });

    for _ in 0..10000 {
        scalars.push(FF::rand(&mut rng));
        points_a.push(GGA::rand(&mut rng));
    }
    c.bench_function("MUL Pedersen vector commitment (with 11128 generators) GG::msm", |b| {
        b.iter(|| GG::msm(points_a.as_slice(), scalars.as_slice()))
    });        
}

fn benchmark_ecc_fixed_base(c : &mut Criterion) {
    use ark_ec::scalar_mul::fixed_base::FixedBase;

    // Example code using FixedBase::MSM is here:  https://github.com/arkworks-rs/poly-commit/blob/1690ecb26c0cfc3c50155a8a4b409f7465948372/src/kzg10/mod.rs#L66
    // Based on these benchmarks we choose window_size = 7: 8192 precomputed points for 256-bit scalar fields. 
    let G = GG::generator();
    let num_scalars = 1;
    let mut rng = ark_std::test_rng();
    let scalar_size = FF::MODULUS_BIT_SIZE as usize;
    for i in 0..7 {
        let window_size = FixedBase::get_mul_window_size(num_scalars) + i;
        let scalar = FF::rand(&mut rng);
        let table_G =
            FixedBase::get_window_table::<GG>(scalar_size, window_size, G);
        c.bench_function(&format!("FBMUL Creating table for G, window size = {}", window_size), |b| {
            b.iter(|| FixedBase::get_window_table::<GG>(scalar_size, window_size, G) )
        });

        let _product = FixedBase::msm::<GG>(scalar_size, window_size, &table_G, &[scalar]);

        c.bench_function(&format!("FBMUL Fixed base MSM with {} term, window size = {}", num_scalars, window_size), |b| {
            b.iter(|| FixedBase::msm::<GG>(scalar_size, window_size, &table_G, &[scalar]) )
        });
    }

    // In the code below, we try computing many values s_i * G at once; but it's slower than computing them separately

    let window_size = 7;
    let mut scalars = Vec::with_capacity(256);
    for _ in 0..scalars.capacity() {
        scalars.push(FF::rand(&mut rng));
    }
    let table_G =
        FixedBase::get_window_table::<GG>(scalar_size, window_size, G);
    c.bench_function(&format!("FBMUL Creating table for G, window size = {}", window_size), |b| {
        b.iter(|| FixedBase::get_window_table::<GG>(scalar_size, window_size, G) )
    });

    c.bench_function(&format!("FBMUL Fixed base MSM with {} terms, window size = {}", scalars.len(), window_size), |b| {
        b.iter(|| FixedBase::msm::<GG>(scalar_size, window_size, &table_G, &scalars.as_slice()) )
    });

}

fn benchmark_dkgith(c: &mut Criterion) {

    let params = CurveParams::init();
    let pke = Elgamal::setup(&params);

    for (N, tau, n) in dkgith::VE_PARAMS {
        let vparams = DkgithParams{ N, tau, n};
        let mut ve = Dkgith::setup(&params, &vparams, pke.clone());
        let dk = ve.kgen();
        let (stm, wit) = ve.igen();

        let pi = ve.prove(&stm, &wit);
        c.bench_function(&format!("DKGitH VE Prove() N = {}, tau = {}, n = {} ", N, tau, n), |b| {
            b.iter(|| ve.prove(&stm, &wit))
        });

        assert!(ve.verify(&stm, &pi));

        c.bench_function(&format!("DKGitH VE Verify() N = {}, tau = {}, n = {} ", N, tau, n), |b| {
            b.iter(|| ve.verify(&stm, &pi))
        });        

        let ve_ct = ve.compress(&stm, &pi);
        c.bench_function(&format!("DKGitH VE Compress() N = {}, tau = {}, n = {} ", N, tau, n), |b| {
            b.iter(|| ve.compress(&stm, &pi))
        });        


        let wit_recover = ve.recover(&stm, &dk, &ve_ct);
        c.bench_function(&format!("DKGitH VE recover() N = {}, tau = {}, n = {} ", N, tau, n), |b| {
            b.iter(|| ve.recover(&stm, &dk, &ve_ct))
        });                

        assert_eq!(wit_recover, wit);
    }

}

fn benchmark_rdkgith(c: &mut Criterion) {

    let params = CurveParams::init();
    let pke = Elgamal::setup(&params);

    for (N, t, n) in rdkgith::RVE_PARAMS {
        let vparams = RDkgithParams{ N, t, n};
        let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
        let dk = ve.kgen();
        let (stm, wit) = ve.igen();

        let pi = ve.prove(&stm, &wit);
        c.bench_function(&format!("RDKGitH VE Prove() N = {}, t = {}, n = {} ", N, t, n), |b| {
            b.iter(|| ve.prove(&stm, &wit))
        });

        assert!(ve.verify(&stm, &pi));

        c.bench_function(&format!("RDKGitH VE Verify() N = {}, t = {}, n = {} ", N, t, n), |b| {
            b.iter(|| ve.verify(&stm, &pi))
        });        

        let ve_ct = ve.compress(&stm, &pi);
        c.bench_function(&format!("RDKGitH VE Compress() N = {}, t = {}, n = {} ", N, t, n), |b| {
            b.iter(|| ve.compress(&stm, &pi))
        });        


        let wit_recover = ve.recover(&stm, &dk, &ve_ct);
        c.bench_function(&format!("RDKGitH VE recover() N = {}, t = {}, n = {} ", N, t, n), |b| {
            b.iter(|| ve.recover(&stm, &dk, &ve_ct))
        });                

        assert_eq!(wit_recover, wit);
    }

}


fn benchmark_camdam(c: &mut Criterion) {

    let params = CurveParams::init();
    let pke = Elgamal::setup(&params);

    for (N, t) in camdam::CDVE_PARAMS {
        let vparams = CDParams{ N, t};
        let mut ve = CD::setup(&params, &vparams, pke.clone());
        let dk = ve.kgen();
        let (stm, wit) = ve.igen();

        let pi = ve.prove(&stm, &wit);
        c.bench_function(&format!("CD00 VE Prove() N = {}, t = {} ", N, t), |b| {
            b.iter(|| ve.prove(&stm, &wit))
        });

        assert!(ve.verify(&stm, &pi));

        c.bench_function(&format!("CD00 VE Verify() N = {}, t = {} ", N, t), |b| {
            b.iter(|| ve.verify(&stm, &pi))
        });        

        let ve_ct = ve.compress(&stm, &pi);
        c.bench_function(&format!("CD00 VE Compress() N = {}, t = {} ", N, t), |b| {
            b.iter(|| ve.compress(&stm, &pi))
        });        


        let wit_recover = ve.recover(&stm, &dk, &ve_ct);
        c.bench_function(&format!("CD00 VE recover() N = {}, t = {} ", N, t), |b| {
            b.iter(|| ve.recover(&stm, &dk, &ve_ct))
        });                

        assert_eq!(wit_recover, wit);
    }

}


criterion_group!(
    benches,
    benchmark_ecc,
    benchmark_ecc_fixed_base,
    benchmark_dkgith, 
    benchmark_rdkgith,
    benchmark_camdam,

);
criterion_main!(benches);