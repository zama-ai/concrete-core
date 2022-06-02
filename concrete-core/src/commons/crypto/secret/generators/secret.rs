use crate::commons::math::random::{
    ByteRandomGenerator, Gaussian, RandomGenerable, RandomGenerator, Seed,
};
use crate::commons::math::tensor::Tensor;
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::dispersion::DispersionParameter;
#[cfg(feature = "generator_x86_64_aesni")]
use concrete_csprng::generators::AesniRandomGenerator;
use concrete_csprng::generators::{RandomGeneratorImplementation, SoftwareRandomGenerator};

/// A random number generator which can be used to generate secret keys.
pub struct SecretRandomGenerator<G: ByteRandomGenerator>(RandomGenerator<G>);

#[cfg(feature = "generator_x86_64_aesni")]
impl SecretRandomGenerator<AesniRandomGenerator> {
    /// Creates a new generator, seeding it with the given value.
    pub fn new(seed: Seed) -> Self {
        SecretRandomGenerator(RandomGenerator::<AesniRandomGenerator>::new(seed))
    }
}

impl SecretRandomGenerator<SoftwareRandomGenerator> {
    /// Creates a new generator, seeding it with the given value.
    pub fn new(seed: Seed) -> Self {
        SecretRandomGenerator(RandomGenerator::<SoftwareRandomGenerator>::new(seed))
    }
}

/// Trait providing utilities to generate random numbers for secret material, like keys, generation.
pub trait SecretRandomGeneratorInterface {
    /// Returns the number of remaining bytes, if the generator is bounded.
    fn remaining_bytes(&self) -> Option<usize>;

    /// Returns a tensor with random uniform binary values.
    fn random_binary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus;
    /// Returns a tensor with random uniform ternary values.
    fn random_ternary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus;

    /// Returns a tensor with random uniform values.
    fn random_uniform_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus;

    /// Returns a tensor with random gaussian values.
    fn random_gaussian_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Scalar: UnsignedTorus;
}

impl<G: ByteRandomGenerator> SecretRandomGeneratorInterface for SecretRandomGenerator<G> {
    fn remaining_bytes(&self) -> Option<usize> {
        self.0.remaining_bytes()
    }

    fn random_binary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        self.0.random_uniform_binary_tensor(length)
    }

    fn random_ternary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        self.0.random_uniform_ternary_tensor(length)
    }

    fn random_uniform_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        self.0.random_uniform_tensor(length)
    }

    fn random_gaussian_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Scalar: UnsignedTorus,
    {
        self.0
            .random_gaussian_tensor(length, 0.0, Scalar::GAUSSIAN_KEY_LOG_STD.get_standard_dev())
    }
}

/// Enum dispatch version of [`SecretRandomGenerator`].
pub enum DynamicSecretRandomGenerator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(SecretRandomGenerator<AesniRandomGenerator>),
    Software(SecretRandomGenerator<SoftwareRandomGenerator>),
}

impl DynamicSecretRandomGenerator {
    pub fn new(random_generator_backend: &RandomGeneratorImplementation, seed: Seed) -> Self {
        match random_generator_backend {
            #[cfg(feature = "generator_x86_64_aesni")]
            RandomGeneratorImplementation::Aesni => DynamicSecretRandomGenerator::Aesni(
                SecretRandomGenerator::<AesniRandomGenerator>::new(seed),
            ),
            RandomGeneratorImplementation::Software => {
                DynamicSecretRandomGenerator::Software(SecretRandomGenerator::<
                    SoftwareRandomGenerator,
                >::new(seed))
            }
        }
    }
}

impl SecretRandomGeneratorInterface for DynamicSecretRandomGenerator {
    fn remaining_bytes(&self) -> Option<usize> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicSecretRandomGenerator::Aesni(inner) => inner.remaining_bytes(),
            DynamicSecretRandomGenerator::Software(inner) => inner.remaining_bytes(),
        }
    }

    fn random_binary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicSecretRandomGenerator::Aesni(inner) => inner.random_binary_tensor(length),
            DynamicSecretRandomGenerator::Software(inner) => inner.random_binary_tensor(length),
        }
    }

    fn random_ternary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicSecretRandomGenerator::Aesni(inner) => inner.random_ternary_tensor(length),
            DynamicSecretRandomGenerator::Software(inner) => inner.random_ternary_tensor(length),
        }
    }

    fn random_uniform_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicSecretRandomGenerator::Aesni(inner) => inner.random_uniform_tensor(length),
            DynamicSecretRandomGenerator::Software(inner) => inner.random_uniform_tensor(length),
        }
    }

    fn random_gaussian_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Scalar: UnsignedTorus,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicSecretRandomGenerator::Aesni(inner) => inner.random_gaussian_tensor(length),
            DynamicSecretRandomGenerator::Software(inner) => inner.random_gaussian_tensor(length),
        }
    }
}
