use concrete_core::backends::fft::private::crypto::bootstrap::FourierLweBootstrapKey;
use concrete_core::commons::crypto::glwe::GlweCiphertext;
use concrete_core::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(feature = "backend_fft")]
    {
        use aligned_vec::avec;
        use dyn_stack::{DynStack, GlobalMemBuffer, ReborrowMut};

        use concrete_core::backends::fft::private as fft;
        use concrete_core::commons::math::torus::{CastInto, UnsignedTorus};
        use concrete_core::prelude::*;

        use fft::c64;
        use fft::crypto::ggsw::{
            external_product, external_product_scratch, FourierGgswCiphertext,
        };
        use fft::crypto::wop_pbs::{extract_bits, extract_bits_scratch};
        use fft::math::fft::Fft;

        fn external_product_bench<Scalar: UnsignedTorus>(n: usize, b: &mut criterion::Bencher) {
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

        fn extract_bits_bench<Scalar: UnsignedTorus + CastInto<usize>>(
            n: usize,
            b: &mut criterion::Bencher,
        ) {
            let polynomial_size = PolynomialSize(n);
            let rlwe_dimension = GlweDimension(1);
            let lwe_dimension = LweDimension(585);

            let level_bsk = DecompositionLevelCount(2);
            let base_log_bsk = DecompositionBaseLog(10);

            let level_ksk = DecompositionLevelCount(7);
            let base_log_ksk = DecompositionBaseLog(4);
            let ksk_input_size = LweDimension(rlwe_dimension.0 * polynomial_size.0);

            let number_of_bits_of_message_including_padding = 5_usize;
            let delta_log = DeltaLog(Scalar::BITS - number_of_bits_of_message_including_padding);
            let number_values_to_extract = ExtractedBitsCount(Scalar::BITS - delta_log.0);

            let ksk = LweKeyswitchKey::from_container(
                avec![Scalar::ZERO; level_ksk.0 * (lwe_dimension.0 + 1) * ksk_input_size.0],
                base_log_ksk,
                level_ksk,
                lwe_dimension,
            );

            let fourier_bsk = FourierLweBootstrapKey::new(
                avec![
                    c64::default();
                    lwe_dimension.0 * polynomial_size.0 / 2
                        * level_bsk.0
                        * rlwe_dimension.to_glwe_size().0
                        * rlwe_dimension.to_glwe_size().0
                ],
                lwe_dimension,
                polynomial_size,
                rlwe_dimension.to_glwe_size(),
                base_log_bsk,
                level_bsk,
            );

            let fft = Fft::new(polynomial_size);
            let fft = fft.as_view();

            let req = extract_bits_scratch::<u64>(
                lwe_dimension,
                ksk.after_key_size(),
                rlwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap();
            let mut mem = GlobalMemBuffer::new(req);
            let mut stack = DynStack::new(&mut mem);

            let lwe_in = LweCiphertext::from_container(
                avec![Scalar::ZERO; LweSize(polynomial_size.0 + 1).0],
            );
            let mut lwe_out_list = LweList::from_container(
                avec![Scalar::ZERO; ksk.lwe_size().0 * number_values_to_extract.0],
                ksk.lwe_size(),
            );

            b.iter(|| {
                extract_bits(
                    lwe_out_list.as_mut_view(),
                    lwe_in.as_view(),
                    ksk.as_view(),
                    fourier_bsk.as_view(),
                    delta_log,
                    number_values_to_extract,
                    fft,
                    stack.rb_mut(),
                );
            });
        }

        let polynomial_sizes = [512, 1024, 2048, 4096, 8192, 16384];

        for n in polynomial_sizes {
            c.bench_function(&format!("fft-external-product-u32-{n}"), |b| {
                external_product_bench::<u32>(n, b);
            });
        }

        for n in polynomial_sizes {
            c.bench_function(&format!("fft-external-product-u64-{n}"), |b| {
                external_product_bench::<u64>(n, b);
            });
        }

        for n in polynomial_sizes {
            c.bench_function(&format!("fft-extract-bits-u32-{n}"), |b| {
                extract_bits_bench::<u32>(n, b);
            });
        }

        for n in polynomial_sizes {
            c.bench_function(&format!("fft-extract-bits-u64-{n}"), |b| {
                extract_bits_bench::<u64>(n, b);
            });
        }
    }

    let _c = c;
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
