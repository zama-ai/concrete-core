use concrete_core::commons::crypto::glwe::GlweCiphertext;
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(feature = "backend_fft")]
    {
        use aligned_vec::avec;
        use concrete_core::backends::fft::private as fft;
        use concrete_core::commons::math::torus::UnsignedTorus;
        use concrete_core::prelude::*;
        use dyn_stack::{DynStack, GlobalMemBuffer, ReborrowMut};

        use fft::c64;
        use fft::crypto::ggsw::{
            external_product, external_product_scratch, FourierGgswCiphertext,
        };
        use fft::math::fft::Fft;

        fn run_bench<Scalar: UnsignedTorus>(n: usize, b: &mut criterion::Bencher) {
            let polynomial_size = PolynomialSize(n);
            let glwe_size = GlweSize(3);
            let decomposition_level_count = DecompositionLevelCount(4);
            let decomposition_base_log = DecompositionBaseLog(2);

            let mut out = GlweCiphertext::from_container(
                avec![Scalar::ZERO; polynomial_size.0 * glwe_size.0].into_boxed_slice(),
                polynomial_size,
            );
            let ggsw = FourierGgswCiphertext::new(
                avec![
                c64::default();
                polynomial_size.0 / 2 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0
                ]
                .into_boxed_slice(),
                polynomial_size,
                glwe_size,
                decomposition_base_log,
                decomposition_level_count,
            );
            let glwe = GlweCiphertext::from_container(
                avec![Scalar::ZERO; polynomial_size.0 * glwe_size.0].into_boxed_slice(),
                polynomial_size,
            );
            let fft = Fft::new(polynomial_size);
            let fft = fft.as_view();

            let mut mem = GlobalMemBuffer::new(
                external_product_scratch::<Scalar>(glwe_size, polynomial_size, fft).unwrap(),
            );
            let mut stack = DynStack::new(&mut mem);
            b.iter(|| {
                external_product(
                    out.as_mut_view(),
                    ggsw.as_view(),
                    glwe.as_view(),
                    fft,
                    stack.rb_mut(),
                );
            })
        }

        let polynomial_sizes = [512, 1024, 2048, 4096, 8192, 16384];

        for n in polynomial_sizes {
            c.bench_function(&format!("fft-external-product-u32-{n}"), |b| {
                run_bench::<u32>(n, b);
            });
        }

        for n in polynomial_sizes {
            c.bench_function(&format!("fft-external-product-u64-{n}"), |b| {
                run_bench::<u64>(n, b);
            });
        }
    }

    let _c = c;
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
