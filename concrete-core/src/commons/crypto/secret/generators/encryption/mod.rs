use crate::commons::math::random::{
    ByteRandomGenerator, Gaussian, RandomGenerable, RandomGenerator,
    RandomGeneratorChildrenIterator, Seed, Seeder, Uniform,
};
use crate::commons::math::tensor::AsMutTensor;

use concrete_commons::dispersion::DispersionParameter;
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{
    DecompositionLevelCount, GlweDimension, GlweSize, LweDimension, LweSize, PolynomialSize,
};
#[cfg(feature = "generator_x86_64_aesni")]
use concrete_csprng::generators::AesniRandomGenerator;
use concrete_csprng::generators::{
    ForkError, RandomGeneratorImplementation, SoftwareRandomGenerator,
};

#[cfg(feature = "parallel")]
mod parallel;
#[cfg(feature = "parallel")]
pub use parallel::*;

/// A random number generator which can be used to encrypt messages.
pub struct EncryptionRandomGenerator<G: ByteRandomGenerator> {
    // A separate mask generator, only used to generate the mask elements.
    mask: RandomGenerator<G>,
    // A separate noise generator, only used to generate the noise elements.
    noise: RandomGenerator<G>,
}

#[cfg(feature = "generator_x86_64_aesni")]
impl EncryptionRandomGenerator<AesniRandomGenerator> {
    /// Creates a new encryption random generator using the [`AesniRandomGenerator`] as the byte
    /// random generator, seeding it with the given value. The seeder is used to seed the private
    /// noise generator.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seed: Seed, seeder: &mut S) -> Self {
        EncryptionRandomGenerator {
            mask: RandomGenerator::<AesniRandomGenerator>::new(seed),
            noise: RandomGenerator::<AesniRandomGenerator>::new(seeder.seed()),
        }
    }
}

impl EncryptionRandomGenerator<SoftwareRandomGenerator> {
    /// Creates a new encryption random generator using the [`SoftwareRandomGenerator`] as the byte
    /// random generator, seeding it with the given value. The seeder is used to seed the private
    /// noise generator.
    // S is ?Sized to allow Box<dyn Seeder> to be passed.
    pub fn new<S: Seeder + ?Sized>(seed: Seed, seeder: &mut S) -> Self {
        EncryptionRandomGenerator {
            mask: RandomGenerator::<SoftwareRandomGenerator>::new(seed),
            noise: RandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed()),
        }
    }
}

#[cfg(test)]
impl EncryptionRandomGenerator<SoftwareRandomGenerator> {
    // Allows to seed the noise generator. For testing purpose only.
    pub fn seed_noise_generator(&mut self, seed: Seed) {
        println!("WARNING: The noise generator of the encryption random generator was seeded.");
        self.noise = RandomGenerator::<SoftwareRandomGenerator>::new(seed);
    }
}

/// Trait that provides random number generation for encryption.
///
/// This trait is implemented by [`EncryptionRandomGenerator`] as well as
/// [`DynamicEncryptionRandomGenerator`], allowing to use both interchangeably depending on the use
/// case.
pub trait SequentialEncryptionRandomGeneratorInterface {
    type ChildrenIter: Iterator<Item = Self>;

    /// Returns the number of remaining bytes for the mask generator, if the generator is bounded.
    fn mask_remaining_bytes(&self) -> Option<usize>;

    /// Forks the generator, when splitting a bootstrap key into ggsw ct.
    fn fork_bsk_to_ggsw<T: UnsignedInteger>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw::<T>(level, glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator, when splitting a ggsw into level matrices.
    fn fork_ggsw_to_ggsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw_level::<T>(glwe_size, polynomial_size);
        let noise_bytes = noise_bytes_per_ggsw_level(glwe_size, polynomial_size);
        self.try_fork(level.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator, when splitting a ggsw level matrix to glwe.
    fn fork_ggsw_level_to_glwe<T: UnsignedInteger>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), polynomial_size);
        let noise_bytes = noise_bytes_per_glwe(polynomial_size);
        self.try_fork(glwe_size.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator, when splitting a ggsw into level matrices.
    fn fork_gsw_to_gsw_levels<T: UnsignedInteger>(
        &mut self,
        level: DecompositionLevelCount,
        lwe_size: LweSize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_gsw_level::<T>(lwe_size);
        let noise_bytes = noise_bytes_per_gsw_level(lwe_size);
        self.try_fork(level.0, mask_bytes, noise_bytes)
    }

    /// Forks the generator, when splitting a ggsw level matrix to glwe.
    fn fork_gsw_level_to_lwe<T: UnsignedInteger>(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension());
        let noise_bytes = noise_bytes_per_lwe();
        self.try_fork(lwe_size.0, mask_bytes, noise_bytes)
    }

    /// Forks both generators into an iterator
    fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<Self::ChildrenIter, ForkError>;

    /// Fills the tensor with random uniform values, using the mask generator.
    fn fill_tensor_with_random_mask<Scalar, Tensorable>(&mut self, output: &mut Tensorable)
    where
        Scalar: RandomGenerable<Uniform>,
        Tensorable: AsMutTensor<Element = Scalar>;

    /// Sample a noise value, using the noise generator.
    fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
    where
        Scalar: RandomGenerable<Gaussian<f64>>;

    /// Fills the input tensor with random noise, using the noise generator.
    fn fill_tensor_with_random_noise<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        std: impl DispersionParameter,
    ) where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Tensorable: AsMutTensor<Element = Scalar>;
}

/// A type alias for the children iterator closure type.
type ChildrenClosure<G> =
    fn((RandomGenerator<G>, RandomGenerator<G>)) -> EncryptionRandomGenerator<G>;

/// A type alias for the children iterator type.
type ChildrenIterator<G> = std::iter::Map<
    std::iter::Zip<RandomGeneratorChildrenIterator<G>, RandomGeneratorChildrenIterator<G>>,
    ChildrenClosure<G>,
>;

/// Result iterator for [`SequentialEncryptionRandomGeneratorInterface::try_fork`] when implemented
/// for [`EncryptionRandomGenerator`].
pub struct EncryptionChildrenIterator<G: ByteRandomGenerator>(ChildrenIterator<G>);

impl<G: ByteRandomGenerator> Iterator for EncryptionChildrenIterator<G> {
    type Item = EncryptionRandomGenerator<G>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<G: ByteRandomGenerator> SequentialEncryptionRandomGeneratorInterface
    for EncryptionRandomGenerator<G>
{
    type ChildrenIter = EncryptionChildrenIterator<G>;

    fn mask_remaining_bytes(&self) -> Option<usize> {
        self.mask.remaining_bytes()
    }

    fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        // We try to fork the generators
        let mask_iter = self.mask.try_fork(n_child, mask_bytes)?;
        let noise_iter = self.noise.try_fork(n_child, noise_bytes)?;

        // We return a proper iterator.
        Ok(EncryptionChildrenIterator::<G>(
            mask_iter
                .zip(noise_iter)
                .map(|(mask, noise)| EncryptionRandomGenerator { mask, noise }),
        ))
    }

    fn fill_tensor_with_random_mask<Scalar, Tensorable>(&mut self, output: &mut Tensorable)
    where
        Scalar: RandomGenerable<Uniform>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        self.mask.fill_tensor_with_random_uniform(output)
    }

    fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
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

    fn fill_tensor_with_random_noise<Scalar, Tensorable>(
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

// Because the internal random number generation API of concrete-core uses generics (we may want to
// re-evaluate that choice) to be able to use the runtime dispatch with DefaultEngine, we have to
// re-write the enum dispatch pattern for EncryptionRandomGenerator here. The generation trait with
// associated ChildrenIter type is not object safe and we therefore cannot use a Box<dyn>, we
// therefore re-use this enum dispatch pattern we also use in concrete-csprng to be able to store a
// Dynamic version of the EncryptionRandomGenerator in the DefaultEngine.

/// Enum dispatch for [`EncryptionRandomGenerator`].
pub enum DynamicEncryptionRandomGenerator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(EncryptionRandomGenerator<AesniRandomGenerator>),
    Software(EncryptionRandomGenerator<SoftwareRandomGenerator>),
}

impl DynamicEncryptionRandomGenerator {
    pub fn new<S: Seeder + ?Sized>(
        random_generator_backend: &RandomGeneratorImplementation,
        seed: Seed,
        seeder: &mut S,
    ) -> Self {
        match random_generator_backend {
            #[cfg(feature = "generator_x86_64_aesni")]
            RandomGeneratorImplementation::Aesni => {
                DynamicEncryptionRandomGenerator::Aesni(EncryptionRandomGenerator::<
                    AesniRandomGenerator,
                >::new(seed, seeder))
            }
            RandomGeneratorImplementation::Software => {
                DynamicEncryptionRandomGenerator::Software(EncryptionRandomGenerator::<
                    SoftwareRandomGenerator,
                >::new(seed, seeder))
            }
        }
    }
}

/// Result iterator for [`SequentialEncryptionRandomGeneratorInterface::try_fork`] when implemented
/// for [`DynamicEncryptionRandomGenerator`].
pub enum DynamicEncryptionRandomGeneratorChildrenIterator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(EncryptionChildrenIterator<AesniRandomGenerator>),
    Software(EncryptionChildrenIterator<SoftwareRandomGenerator>),
}

impl Iterator for DynamicEncryptionRandomGeneratorChildrenIterator {
    type Item = DynamicEncryptionRandomGenerator;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGeneratorChildrenIterator::Aesni(inner) => {
                inner.next().map(DynamicEncryptionRandomGenerator::Aesni)
            }
            DynamicEncryptionRandomGeneratorChildrenIterator::Software(inner) => {
                inner.next().map(DynamicEncryptionRandomGenerator::Software)
            }
        }
    }
}

impl SequentialEncryptionRandomGeneratorInterface for DynamicEncryptionRandomGenerator {
    type ChildrenIter = DynamicEncryptionRandomGeneratorChildrenIterator;

    fn mask_remaining_bytes(&self) -> Option<usize> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGenerator::Aesni(inner) => inner.mask_remaining_bytes(),
            DynamicEncryptionRandomGenerator::Software(inner) => inner.mask_remaining_bytes(),
        }
    }

    fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
        noise_bytes: usize,
    ) -> Result<Self::ChildrenIter, ForkError> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGenerator::Aesni(inner) => {
                let children_iter = inner.try_fork(n_child, mask_bytes, noise_bytes)?;
                Ok(DynamicEncryptionRandomGeneratorChildrenIterator::Aesni(
                    children_iter,
                ))
            }
            DynamicEncryptionRandomGenerator::Software(inner) => {
                let children_iter = inner.try_fork(n_child, mask_bytes, noise_bytes)?;
                Ok(DynamicEncryptionRandomGeneratorChildrenIterator::Software(
                    children_iter,
                ))
            }
        }
    }

    fn fill_tensor_with_random_mask<Scalar, Tensorable>(&mut self, output: &mut Tensorable)
    where
        Scalar: RandomGenerable<Uniform>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGenerator::Aesni(inner) => {
                inner.fill_tensor_with_random_mask(output)
            }
            DynamicEncryptionRandomGenerator::Software(inner) => {
                inner.fill_tensor_with_random_mask(output)
            }
        }
    }

    fn random_noise<Scalar>(&mut self, std: impl DispersionParameter) -> Scalar
    where
        Scalar: RandomGenerable<Gaussian<f64>>,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGenerator::Aesni(inner) => inner.random_noise(std),
            DynamicEncryptionRandomGenerator::Software(inner) => inner.random_noise(std),
        }
    }

    fn fill_tensor_with_random_noise<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        std: impl DispersionParameter,
    ) where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicEncryptionRandomGenerator::Aesni(inner) => {
                inner.fill_tensor_with_random_noise(output, std)
            }
            DynamicEncryptionRandomGenerator::Software(inner) => {
                inner.fill_tensor_with_random_noise(output, std)
            }
        }
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

fn mask_bytes_per_ggsw_level<T: UnsignedInteger>(
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    glwe_size.0 * mask_bytes_per_glwe::<T>(glwe_size.to_glwe_dimension(), poly_size)
}

fn mask_bytes_per_lwe<T: UnsignedInteger>(lwe_dimension: LweDimension) -> usize {
    lwe_dimension.0 * mask_bytes_per_coef::<T>()
}

fn mask_bytes_per_gsw_level<T: UnsignedInteger>(lwe_size: LweSize) -> usize {
    lwe_size.0 * mask_bytes_per_lwe::<T>(lwe_size.to_lwe_dimension())
}

fn mask_bytes_per_ggsw<T: UnsignedInteger>(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * mask_bytes_per_ggsw_level::<T>(glwe_size, poly_size)
}

fn noise_bytes_per_coef() -> usize {
    // We use f64 to sample the noise for every precision, and we need 4/pi inputs to generate
    // such an output (here we take 32 to keep a safety margin).
    8 * 32
}
fn noise_bytes_per_polynomial(poly_size: PolynomialSize) -> usize {
    poly_size.0 * noise_bytes_per_coef()
}

fn noise_bytes_per_glwe(poly_size: PolynomialSize) -> usize {
    noise_bytes_per_polynomial(poly_size)
}

fn noise_bytes_per_ggsw_level(glwe_size: GlweSize, poly_size: PolynomialSize) -> usize {
    glwe_size.0 * noise_bytes_per_glwe(poly_size)
}

fn noise_bytes_per_lwe() -> usize {
    // Here we take 3 to keep a safety margin
    noise_bytes_per_coef() * 3
}

fn noise_bytes_per_gsw_level(lwe_size: LweSize) -> usize {
    lwe_size.0 * noise_bytes_per_lwe()
}

fn noise_bytes_per_ggsw(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * noise_bytes_per_ggsw_level(glwe_size, poly_size)
}
