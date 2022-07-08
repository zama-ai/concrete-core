#[cfg(feature = "__commons_parallel")]
use crate::commons::math::random::ParallelByteRandomGenerator;
use crate::commons::math::random::{
    ByteRandomGenerator, Gaussian, RandomGenerable, RandomGenerator, Seed, Seeder, Uniform,
};
use crate::commons::math::tensor::AsMutTensor;

use concrete_commons::dispersion::DispersionParameter;
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{
    DecompositionLevelCount, GlweDimension, GlweSize, LweDimension, LweSize, PolynomialSize,
};
use concrete_csprng::generators::ForkError;
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;
use crate::prelude::GlevCount;

/// A random number generator which can be used to encrypt messages.
pub struct EncryptionRandomGenerator<G: ByteRandomGenerator> {
    // A separate mask generator, only used to generate the mask elements.
    mask: RandomGenerator<G>,
    // A separate noise generator, only used to generate the noise elements.
    noise: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> EncryptionRandomGenerator<G> {
    /// Creates a new encryption, optionally seeding it with the given value.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seed: Seed, seeder: &mut S) -> EncryptionRandomGenerator<G> {
        EncryptionRandomGenerator {
            mask: RandomGenerator::new(seed),
            noise: RandomGenerator::new(seeder.seed()),
        }
    }

    // Allows to seed the noise generator. For testing purpose only.
    #[cfg(test)]
    pub(crate) fn seed_noise_generator(&mut self, seed: Seed) {
        println!("WARNING: The noise generator of the encryption random generator was seeded.");
        self.noise = RandomGenerator::new(seed);
    }

    /// Returns the number of remaining bytes for the mask generator, if the generator is bounded.
    pub fn remaining_bytes(&self) -> Option<usize> {
        self.mask.remaining_bytes()
    }

    // Forks the generator, when splitting a bootstrap key into ggsw ct.
    #[allow(dead_code)]
    pub(crate) fn fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glev_list::<T>(level, glwe_size, GlevCount
            (glwe_size.0), polynomial_size);
        let noise_bytes = noise_bytes_per_glev_list(level, GlevCount(glwe_size.0), polynomial_size);
        self.try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a vector of Glevs into level matrices.
    pub(crate) fn fork_glev_list_to_glev_list_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        glev_count: GlevCount,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glev_list_level::<T>(glwe_size, glev_count, 
                                                             polynomial_size);
        let noise_bytes = noise_bytes_per_glev_list_level(glev_count, polynomial_size);
        self.try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a Glev list level matrix to GLWE.
    pub(crate) fn fork_glev_list_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        glev_count: GlevCount,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), polynomial_size);
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.try_fork(glev_count.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a gsw into level matrices.
    pub(crate) fn fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_gsw_level::<T>(lwe_size);
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator, when splitting a gsw level matrix to lwe.
    pub(crate) fn fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks both generators into an iterator
    fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<impl Iterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.mask.try_fork(n_child, mask_bytes)?;
        let noise_iter = self.noise.try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }))
    }

    // Fills the tensor with random uniform values, using the mask generator.
    pub(crate) fn fill_tensor_with_random_mask<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
    ) where
        Scalar: RandomGenerable<Uniform>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        self.mask.fill_tensor_with_random_uniform(output)
    }

    // Sample a noise value, using the noise generator.
    pub(crate) fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
    where
        Scalar: RandomGenerable<Gaussian<f64>>,
    {
        <Scalar>::generate_one(
            &mut self.noise,
            Gaussian {
                std: std.get_standard_dev(),
                mean: 0.,
            },
        )
    }

    // Fills the input tensor with random noise, using the noise generator.
    pub(crate) fn fill_tensor_with_random_noise<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        std: impl DispersionParameter,
    ) where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        self.noise
            .fill_tensor_with_random_gaussian(output, 0., std.get_standard_dev());
    }
}

#[cfg(feature = "__commons_parallel")]
impl<G: ParallelByteRandomGenerator> EncryptionRandomGenerator<G> {
    // Forks the generator into a parallel iterator, when splitting a bootstrap key into ggsw ct.
    pub(crate) fn par_fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glev_list::<T>(level, glwe_size, GlevCount
            (glwe_size.0), polynomial_size);
        let noise_bytes = noise_bytes_per_glev_list(level, GlevCount(glwe_size.0), polynomial_size);
        self.par_try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a Glev list into level matrices.
    pub(crate) fn par_fork_glev_list_to_glev_list_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        glev_count: GlevCount,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glev_list_level::<T>(glwe_size, glev_count, 
                                                             polynomial_size);
        let noise_bytes = noise_bytes_per_glev_list_level(glev_count, polynomial_size);
        self.par_try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a Glev list level matrix to 
    // GLWE.
    pub(crate) fn par_fork_glev_list_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        glev_count: GlevCount,
        polynomial_size: PolynomialSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), polynomial_size);
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.par_try_fork(glev_count.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw into level matrices.
    pub(crate) fn par_fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_gsw_level::<T>(lwe_size);
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.par_try_fork(level.0, mask_bytes, noise_bytes)
    }

    // Forks the generator into a parallel iterator, when splitting a ggsw level matrix to glwe.
    pub(crate) fn par_fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.par_try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    // Forks both generators into a parallel iterator.
    fn par_try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<impl IndexedParallelIterator<Item = EncryptionRandomGenerator<G>>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.mask.par_try_fork(n_child, mask_bytes)?;
        let noise_iter = self.noise.par_try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(mask_iter
            .zip(noise_iter)
            .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }))
    }
}

fn mask_bytes_per_coef<T: UnsignedInteger>() -> usize {
    T::BITS / 8
}

fn mask_bytes_per_polynomial<T: UnsignedInteger>(poly_size: PolynomialSize) -> usize {
    poly_size.0 * mask_bytes_per_coef::<T>()
}

fn mask_bytes_per_glwe<T: UnsignedInteger>(
    glwe_dimension: GlweDimension,
    poly_size: PolynomialSize,
) -> usize {
    glwe_dimension.0 * mask_bytes_per_polynomial::<T>(poly_size)
}

fn mask_bytes_per_glev_list_level<T: UnsignedInteger>(
    glwe_size: GlweSize,
    glev_count: GlevCount,
    poly_size: PolynomialSize,
) -> usize {
    glev_count.0 * mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), poly_size)
}

fn mask_bytes_per_lwe<T: UnsignedInteger>(lwe_dimension: LweDimension) -> usize {
    lwe_dimension.0 * mask_bytes_per_coef::<T>()
}

fn mask_bytes_per_gsw_level<T: UnsignedInteger>(lwe_size: LweSize) -> usize {
    lwe_size.0 * mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension())
}

fn mask_bytes_per_glev_list<T: UnsignedInteger>(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    glev_count: GlevCount,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * mask_bytes_per_glev_list_level::<T>(glwe_size, glev_count, poly_size)
}

fn noise_bytes_per_coef() -> usize {
    // We use f64 to sample the noise for every precision, and we need 4/pi inputs to generate
    // such an output (here we take 32 to keep a safety margin).
    // TODO: check this value
    8 * 32
}
fn noise_bytes_per_polynomial(poly_size: PolynomialSize) -> usize {
    poly_size.0 * noise_bytes_per_coef()
}

fn noise_bytes_per_glwe(poly_size: PolynomialSize) -> usize {
    noise_bytes_per_polynomial(poly_size)
}

fn noise_bytes_per_glev_list_level(glev_count: GlevCount, poly_size: PolynomialSize) -> 
                                                                                           usize {
    glev_count.0 * noise_bytes_per_glwe(poly_size)
}

fn noise_bytes_per_lwe() -> usize {
    // Here we take 3 to keep a safety margin
    noise_bytes_per_coef() * 3
}

fn noise_bytes_per_gsw_level(lwe_size: LweSize) -> usize {
    lwe_size.0 * noise_bytes_per_lwe()
}

fn noise_bytes_per_glev_list(
    level: DecompositionLevelCount,
    glev_count: GlevCount,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * noise_bytes_per_glev_list_level(glev_count, poly_size)
}

#[cfg(all(test, feature = "parallel"))]
mod test {
    use crate::commons::crypto::bootstrap::StandardBootstrapKey;
    use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::commons::test_tools::{
        new_encryption_random_generator, new_secret_random_generator,
    };
    use concrete_commons::dispersion::Variance;
    use concrete_commons::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    };

    #[test]
    fn test_gaussian_sampling_margin_factor_does_not_panic() {
        struct Params {
            glwe_size: GlweSize,
            poly_size: PolynomialSize,
            dec_level_count: DecompositionLevelCount,
            dec_base_log: DecompositionBaseLog,
            lwe_dim: LweDimension,
        }
        let params = Params {
            glwe_size: GlweSize(2),
            poly_size: PolynomialSize(1),
            dec_level_count: DecompositionLevelCount(1),
            dec_base_log: DecompositionBaseLog(4),
            lwe_dim: LweDimension(17000),
        };
        let mut enc_generator = new_encryption_random_generator();
        let mut sec_generator = new_secret_random_generator();
        let mut bsk = StandardBootstrapKey::allocate(
            0u32,
            params.glwe_size,
            params.poly_size,
            params.dec_level_count,
            params.dec_base_log,
            params.lwe_dim,
        );
        let lwe_sk = LweSecretKey::generate_binary(params.lwe_dim, &mut sec_generator);
        let glwe_sk = GlweSecretKey::generate_binary(
            params.glwe_size.to_glwe_dimension(),
            params.poly_size,
            &mut sec_generator,
        );
        bsk.par_fill_with_new_key(&lwe_sk, &glwe_sk, Variance(0.), &mut enc_generator);
    }
}
