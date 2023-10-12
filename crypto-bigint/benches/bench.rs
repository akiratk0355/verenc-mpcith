use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BatchSize, BenchmarkGroup, Criterion,
};
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
     Random, U8192, U4096, U6144, U3072, U2048, U1536, U256, U512
};
use rand_core::OsRng;


fn bench_montgomery_ops6144<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let params = DynResidueParams::new(&(U6144::random(&mut OsRng) | U6144::ONE));

    let m = U6144::random(&mut OsRng) | U6144::ONE;
    let params = DynResidueParams::new(&m);
    group.bench_function("modpow, U6144^U6144", |b| {
        b.iter_batched(
            || {
                let x = U6144::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U6144::random(&mut OsRng) | (U6144::ONE << (U6144::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow(&p),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("modpow, U6144^U3072", |b| {
        b.iter_batched(
            || {
                let x = U6144::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U6144::random(&mut OsRng) | (U6144::ONE << (U3072::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U3072::BITS),
            BatchSize::SmallInput,
        )
    }); 

    group.bench_function("modpow, U6144^U512", |b| {
        b.iter_batched(
            || {
                let x = U6144::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U6144::random(&mut OsRng) | (U6144::ONE << (U512::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U512::BITS),
            BatchSize::SmallInput,
        )
    });    
    group.bench_function("modpow, U6144^U256", |b| {
        b.iter_batched(
            || {
                let x = U6144::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U6144::random(&mut OsRng) | (U6144::ONE << (U256::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U256::BITS),
            BatchSize::SmallInput,
        )
    });    
         
}

fn bench_montgomery_ops3072<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let params = DynResidueParams::new(&(U3072::random(&mut OsRng) | U3072::ONE));

    let m = U3072::random(&mut OsRng) | U3072::ONE;
    let params = DynResidueParams::new(&m);
    group.bench_function("modpow, U3072^U3072", |b| {
        b.iter_batched(
            || {
                let x = U3072::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U3072::random(&mut OsRng) | (U3072::ONE << (U3072::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow(&p),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("modpow, U3072^U1536", |b| {
        b.iter_batched(
            || {
                let x = U3072::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U3072::random(&mut OsRng) | (U3072::ONE << (U1536::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U1536::BITS),
            BatchSize::SmallInput,
        )
    }); 

    group.bench_function("modpow, U3072^U512", |b| {
        b.iter_batched(
            || {
                let x = U3072::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U3072::random(&mut OsRng) | (U3072::ONE << (U512::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U512::BITS),
            BatchSize::SmallInput,
        )
    });    
    group.bench_function("modpow, U3072^U256", |b| {
        b.iter_batched(
            || {
                let x = U3072::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U3072::random(&mut OsRng) | (U3072::ONE << (U256::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U256::BITS),
            BatchSize::SmallInput,
        )
    }); 
}

    fn bench_montgomery_ops8192<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let params = DynResidueParams::new(&(U8192::random(&mut OsRng) | U8192::ONE));

    let m = U8192::random(&mut OsRng) | U8192::ONE;
    let params = DynResidueParams::new(&m);
    group.bench_function("modpow, U8192^U8192", |b| {
        b.iter_batched(
            || {
                let x = U8192::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U8192::random(&mut OsRng) | (U8192::ONE << (U8192::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow(&p),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("modpow, U8192^U4096", |b| {
        b.iter_batched(
            || {
                let x = U8192::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U8192::random(&mut OsRng) | (U8192::ONE << (U4096::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U4096::BITS),
            BatchSize::SmallInput,
        )
    }); 

    group.bench_function("modpow, U8192^U512", |b| {
        b.iter_batched(
            || {
                let x = U8192::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U8192::random(&mut OsRng) | (U8192::ONE << (U512::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U512::BITS),
            BatchSize::SmallInput,
        )
    });    
    group.bench_function("modpow, U8192^U256", |b| {
        b.iter_batched(
            || {
                let x = U8192::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U8192::random(&mut OsRng) | (U8192::ONE << (U256::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U256::BITS),
            BatchSize::SmallInput,
        )
    });    
         
}

fn bench_montgomery_ops2048<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let params = DynResidueParams::new(&(U2048::random(&mut OsRng) | U2048::ONE));

    let m = U2048::random(&mut OsRng) | U2048::ONE;
    let params = DynResidueParams::new(&m);

    group.bench_function("modpow, U2048^U2048", |b| {
        b.iter_batched(
            || {
                let x = U2048::random(&mut OsRng);
                let x_m = DynResidue::new(&x, params);
                let p = U2048::random(&mut OsRng) | (U2048::ONE << (U2048::BITS - 1));
                (x_m, p)
            },
            |(x, p)| x.pow_bounded_exp(&p, U2048::BITS),
            BatchSize::SmallInput,
        )
    }); 

         
}



fn bench_montgomery(c: &mut Criterion) {
    let mut group = c.benchmark_group("Montgomery arithmetic");
    
    bench_montgomery_ops8192(&mut group);
    bench_montgomery_ops6144(&mut group);
    bench_montgomery_ops3072(&mut group);
    bench_montgomery_ops2048(&mut group);
    group.finish();
}

criterion_group!(benches, bench_montgomery);
criterion_main!(benches);
