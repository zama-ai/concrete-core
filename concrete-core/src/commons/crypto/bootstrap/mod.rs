//! Bootstrapping keys.
//!
//! The bootstrapping operation allows to reduce the level of noise in an LWE ciphertext, while
//! evaluating an univariate function.

pub use standard::StandardBootstrapKey;

mod standard;

#[cfg(all(test, feature = "multithread"))]
mod test {
    use crate::commons::crypto::bootstrap::StandardBootstrapKey;
    use crate::commons::crypto::secret::generators::EncryptionRandomGenerator;
    use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::commons::math::torus::UnsignedTorus;
    use crate::commons::test_tools::{new_secret_random_generator, UnsafeRandSeeder};
    use concrete_commons::dispersion::StandardDev;
    use concrete_commons::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use concrete_csprng::seeders::Seed;

    fn test_bsk_gen_equivalence<T: UnsignedTorus + Send + Sync>() {
        for _ in 0..10 {
            let lwe_dim = LweDimension(crate::commons::test_tools::random_usize_between(5..10));
            let glwe_dim = GlweDimension(crate::commons::test_tools::random_usize_between(5..10));
            let poly_size = PolynomialSize(crate::commons::test_tools::random_usize_between(5..10));
            let level =
                DecompositionLevelCount(crate::commons::test_tools::random_usize_between(2..5));
            let base_log =
                DecompositionBaseLog(crate::commons::test_tools::random_usize_between(2..5));
            let mask_seed = crate::commons::test_tools::any_usize() as u128;
            let noise_seed = crate::commons::test_tools::any_usize() as u128;

            let mut secret_generator = new_secret_random_generator();
            let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
            let glwe_sk =
                GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);

            let mut mono_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );
            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    Seed(mask_seed),
                    &mut UnsafeRandSeeder,
                );
            encryption_generator.seed_noise_generator(Seed(noise_seed));
            mono_bsk.fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut multi_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );
            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    Seed(mask_seed),
                    &mut UnsafeRandSeeder,
                );
            encryption_generator.seed_noise_generator(Seed(noise_seed));
            multi_bsk.par_fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            assert_eq!(mono_bsk, multi_bsk);
        }
    }

    #[test]
    fn test_bsk_gen_equivalence_u32() {
        test_bsk_gen_equivalence::<u32>()
    }

    #[test]
    fn test_bsk_gen_equivalence_u64() {
        test_bsk_gen_equivalence::<u64>()
    }
}
