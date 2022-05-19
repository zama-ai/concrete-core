#[cfg(feature = "serde_serialize")]
use serde::{Deserialize, Serialize};

use concrete_commons::numeric::Numeric;
use concrete_commons::parameters::{LweDimension, LweSize};

#[cfg(feature = "serde_serialize")]
use crate::commons::math::random::SeedSerdeDef;
use crate::commons::math::random::{
    ByteRandomGenerator, RandomGenerable, RandomGenerator, Seed, Uniform,
};
use crate::commons::math::tensor::AsMutTensor;

use super::{LweBody, LweCiphertext};

/// A seeded ciphertext encrypted using the LWE scheme.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertext<Scalar> {
    pub(crate) body: LweBody<Scalar>,
    pub(crate) lwe_dimension: LweDimension,
    // Use a proxy to serialize/deserialize Seed to avoid adding a serde dependency to
    // concrete-csprng
    #[cfg_attr(feature = "serde_serialize", serde(with = "SeedSerdeDef"))]
    pub(crate) seed: Seed,
    // generator_byte_index is the sequence number of the first byte to generate on a freshly
    // seeded CSPRNG to properly generate the mask of the ciphertext. Technically this should
    // be a u128, but usize is plenty to generate bytes, also `Iterator` APIs take usize.
    pub(crate) generator_byte_index: usize,
}

impl<Scalar: Numeric> LweSeededCiphertext<Scalar> {
    /// Allocates a seeded ciphertext whose body is 0.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{LweDimension, LweSize};
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// let ciphertext = LweSeededCiphertext::allocate(LweDimension(3), Seed(42), 37);
    /// assert_eq!(*ciphertext.get_body(), LweBody(0_u8));
    /// assert_eq!(ciphertext.lwe_size(), LweSize(4));
    /// assert_eq!(ciphertext.get_seed(), Seed(42));
    /// assert_eq!(ciphertext.get_generator_byte_index(), 37);
    /// ```
    pub fn allocate(lwe_dimension: LweDimension, seed: Seed, shift: usize) -> Self {
        Self::from_scalar(Scalar::ZERO, lwe_dimension, seed, shift)
    }

    /// Allocates a new seeded ciphertext from elementary components.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{LweDimension, LweSize};
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), Seed(42), 37);
    /// assert_eq!(*ciphertext.get_body(), LweBody(0_u8));
    /// assert_eq!(ciphertext.lwe_size(), LweSize(4));
    /// assert_eq!(ciphertext.get_seed(), Seed(42));
    /// assert_eq!(ciphertext.get_generator_byte_index(), 37);
    /// ```
    pub fn from_scalar(
        value: Scalar,
        lwe_dimension: LweDimension,
        seed: Seed,
        shift: usize,
    ) -> Self {
        Self {
            body: LweBody(value),
            lwe_dimension,
            seed,
            generator_byte_index: shift,
        }
    }

    /// Returns the size of the ciphertext, e.g. the size of the mask + 1 for the body.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{LweDimension, LweSize};
    /// use concrete_core::commons::crypto::lwe::LweSeededCiphertext;
    /// use concrete_core::commons::math::random::Seed;
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), Seed(42), 37);
    /// assert_eq!(ciphertext.lwe_size(), LweSize(4));
    /// ```
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_dimension.to_lwe_size()
    }

    /// Returns the body of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), Seed(42), 37);
    /// let body = ciphertext.get_body();
    /// assert_eq!(*body, LweBody(0_u8));
    /// ```
    pub fn get_body(&self) -> &LweBody<Scalar> {
        &self.body
    }

    /// Returns the mutable body of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// let mut ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), Seed(42), 37);
    /// let mut body = ciphertext.get_mut_body();
    /// assert_eq!(*body, LweBody(0_u8));
    /// *body = LweBody(8);
    /// let body = ciphertext.get_body();
    /// assert_eq!(body, &LweBody(8_u8));
    /// ```
    pub fn get_mut_body(&mut self) -> &mut LweBody<Scalar> {
        &mut self.body
    }

    /// Returns the seed of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), Seed(42), 37);
    /// assert_eq!(ciphertext.get_seed(), Seed(42));
    /// ```
    pub fn get_seed(&self) -> Seed {
        self.seed
    }

    /// Returns the shift required on a freshly seeded generator to generate the mask of the
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), Seed(42), 37);
    /// assert_eq!(ciphertext.get_generator_byte_index(), 37);
    /// ```
    pub fn get_generator_byte_index(&self) -> usize {
        self.generator_byte_index
    }

    /// Returns the ciphertext as a fully fledged LweCiphertext
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{LweDimension, LweSize};
    /// use concrete_core::commons::crypto::lwe::{LweBody, LweCiphertext, LweSeededCiphertext};
    /// use concrete_core::commons::math::random::Seed;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    ///
    /// let seeded_ciphertext: LweSeededCiphertext<u8> =
    ///     LweSeededCiphertext::allocate(LweDimension(9), Seed(42), 37);
    /// let mut ciphertext = LweCiphertext::allocate(0_u8, LweSize(10));
    /// seeded_ciphertext.expand_into::<_, SoftwareRandomGenerator>(&mut ciphertext);
    /// let (body, mask) = ciphertext.get_mut_body_and_mask();
    /// assert_eq!(body, &mut LweBody(0));
    /// assert_eq!(mask.mask_size(), LweDimension(9));
    /// ```
    pub fn expand_into<Cont, Gen>(self, output: &mut LweCiphertext<Cont>)
    where
        LweCiphertext<Cont>: AsMutTensor<Element = Scalar>,
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.seed);
        generator.shift(self.generator_byte_index);
        let (output_body, mut output_mask) = output.get_mut_body_and_mask();

        // generate a uniformly random mask
        generator.fill_tensor_with_random_uniform(output_mask.as_mut_tensor());

        output_body.0 = self.body.0;
    }
}
