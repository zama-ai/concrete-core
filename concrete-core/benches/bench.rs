use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

// these benchmarks are different from the ones in concrete-core-bench in that they avoid
// randomly initializing their inputs. which significantly reduces the total running time and makes
// it easier to profile the code.
pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(feature = "backend_fft")]
    {
        use aligned_vec::avec;
        use dyn_stack::{DynStack, GlobalMemBuffer, ReborrowMut};

        use concrete_core::backends::fft::private as fft;
        use concrete_core::commons::crypto::encoding::Plaintext;
        use concrete_core::commons::crypto::glwe::{
            GlweCiphertext, LwePrivateFunctionalPackingKeyswitchKeyList,
        };
        use concrete_core::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
        use concrete_core::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
        use concrete_core::commons::math::polynomial::PolynomialList;
        use concrete_core::commons::math::tensor::{AsRefSlice, AsRefTensor};
        use concrete_core::commons::math::torus::{CastInto, UnsignedTorus};
        use concrete_core::prelude::*;
        use fft::crypto::bootstrap::FourierLweBootstrapKey;
        use fft::crypto::wop_pbs::{
            circuit_bootstrap_boolean_vertical_packing,
            circuit_bootstrap_boolean_vertical_packing_scratch,
        };

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

        fn wop_pbs_bench<Scalar: UnsignedTorus + CastInto<usize>>(
            n: usize,
            b: &mut criterion::Bencher,
        ) {
            let polynomial_size = PolynomialSize(n);
            let glwe_dimension = GlweDimension(1);
            let lwe_dimension = LweDimension(481);

            let level_bsk = DecompositionLevelCount(9);
            let base_log_bsk = DecompositionBaseLog(4);

            let level_pksk = DecompositionLevelCount(9);
            let base_log_pksk = DecompositionBaseLog(4);

            let level_ksk = DecompositionLevelCount(9);
            let base_log_ksk = DecompositionBaseLog(1);

            let level_cbs = DecompositionLevelCount(4);
            let base_log_cbs = DecompositionBaseLog(6);

            //create GLWE and LWE secret key
            let glwe_sk: GlweSecretKey<_, Vec<Scalar>> = GlweSecretKey::binary_from_container(
                vec![Scalar::ZERO; polynomial_size.0 * glwe_dimension.0],
                polynomial_size,
            );

            let lwe_small_sk: LweSecretKey<_, Vec<Scalar>> =
                LweSecretKey::binary_from_container(vec![Scalar::ZERO; lwe_dimension.0]);

            let lwe_big_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());

            // allocation for the bootstrapping key
            let fourier_bsk = FourierLweBootstrapKey::new(
                vec![
                    c64::default();
                    lwe_dimension.0 * polynomial_size.0 / 2
                        * level_bsk.0
                        * glwe_dimension.to_glwe_size().0
                        * glwe_dimension.to_glwe_size().0
                ],
                lwe_dimension,
                polynomial_size,
                glwe_dimension.to_glwe_size(),
                base_log_bsk,
                level_bsk,
            );

            let fft = Fft::new(polynomial_size);
            let fft = fft.as_view();

            let ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
                Scalar::ZERO,
                level_ksk,
                base_log_ksk,
                lwe_big_sk.key_size(),
                lwe_small_sk.key_size(),
            );

            // Creation of all the pfksk for the circuit bootstrapping
            let vec_fpksk = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
                Scalar::ZERO,
                level_pksk,
                base_log_pksk,
                lwe_big_sk.key_size(),
                glwe_sk.key_size(),
                glwe_sk.polynomial_size(),
                FunctionalPackingKeyswitchKeyCount(glwe_dimension.to_glwe_size().0),
            );

            let number_of_bits_in_input_lwe = 10;
            let number_of_values_to_extract = ExtractedBitsCount(number_of_bits_in_input_lwe);

            // Here even thought the deltas have the same value, they can differ between ciphertexts
            // and lut so keeping both separate
            let delta_log = DeltaLog(Scalar::BITS - number_of_values_to_extract.0);

            let lwe_in = LweCiphertext::allocate(
                Scalar::ZERO,
                LweSize(glwe_dimension.0 * polynomial_size.0 + 1),
            );
            let mut extracted_bits_lwe_list = LweList::allocate(
                Scalar::ZERO,
                ksk_lwe_big_to_small.lwe_size(),
                CiphertextCount(number_of_values_to_extract.0),
            );

            let mut mem = GlobalMemBuffer::new(
                extract_bits_scratch::<Scalar>(
                    lwe_dimension,
                    ksk_lwe_big_to_small.after_key_size(),
                    fourier_bsk.glwe_size(),
                    polynomial_size,
                    fft,
                )
                .unwrap(),
            );
            extract_bits(
                extracted_bits_lwe_list.as_mut_view(),
                lwe_in.as_view(),
                ksk_lwe_big_to_small.as_view(),
                fourier_bsk.as_view(),
                delta_log,
                number_of_values_to_extract,
                fft,
                DynStack::new(&mut mem),
            );

            // Decrypt all extracted bit for checking purposes in case of problems
            for ct in extracted_bits_lwe_list.ciphertext_iter() {
                let mut decrypted_message = Plaintext(Scalar::ZERO);
                lwe_small_sk.decrypt_lwe(&mut decrypted_message, &ct);
            }

            // LUT creation
            let number_of_luts_and_output_vp_ciphertexts = 1;

            // Test with a big lut, triggering an actual cmux tree
            let lut_poly_list = PolynomialList::allocate(
                Scalar::ZERO,
                PolynomialCount(1 << number_of_bits_in_input_lwe),
                polynomial_size,
            );

            // We need as many output ciphertexts as we have input luts
            let mut vertical_packing_lwe_list_out = LweList::allocate(
                Scalar::ZERO,
                LweDimension(polynomial_size.0 * glwe_dimension.0).to_lwe_size(),
                CiphertextCount(number_of_luts_and_output_vp_ciphertexts),
            );

            // Perform circuit bootstrap + vertical packing
            let mut mem = GlobalMemBuffer::new(
                circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
                    extracted_bits_lwe_list.count(),
                    vertical_packing_lwe_list_out.count(),
                    extracted_bits_lwe_list.lwe_size(),
                    lut_poly_list.polynomial_count(),
                    fourier_bsk.output_lwe_dimension().to_lwe_size(),
                    vec_fpksk.output_polynomial_size(),
                    fourier_bsk.glwe_size(),
                    level_cbs,
                    fft,
                )
                .unwrap(),
            );
            b.iter(|| {
                circuit_bootstrap_boolean_vertical_packing(
                    lut_poly_list.as_view(),
                    fourier_bsk.as_view(),
                    vertical_packing_lwe_list_out.as_mut_view(),
                    extracted_bits_lwe_list.as_view(),
                    vec_fpksk.as_view(),
                    level_cbs,
                    base_log_cbs,
                    fft,
                    DynStack::new(&mut mem),
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

        let polynomial_sizes = [512, 1024, 2048, 4096];
        for n in polynomial_sizes {
            c.bench_function(&format!("fft-wop-pbs-u32-{n}"), |b| {
                wop_pbs_bench::<u32>(n, b);
            });
        }
        for n in polynomial_sizes {
            c.bench_function(&format!("fft-wop-pbs-u64-{n}"), |b| {
                wop_pbs_bench::<u64>(n, b);
            });
        }
    }

    let _c = c;
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(5));
    targets = criterion_benchmark
);
criterion_main!(benches);
