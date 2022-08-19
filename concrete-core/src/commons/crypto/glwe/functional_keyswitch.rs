#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use crate::commons::math::random::ByteRandomGenerator;
use concrete_commons::dispersion::DispersionParameter;
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    LweDimension, MonomialDegree, PlaintextCount, PolynomialSize,
};

use crate::commons::crypto::encoding::PlaintextList;
use crate::commons::crypto::glwe::LweKeyBitDecomposition;
use crate::commons::crypto::lwe::{LweCiphertext, LweList};
use crate::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, SignedDecomposer,
};
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::commons::math::torus::UnsignedTorus;

use super::GlweCiphertext;

/// A packing private functional keyswitching key.
///
/// A packing private functional keyswitching key allows to  pack several LWE ciphertexts into a
/// single GLWE ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionalPackingKeyswitchKey<Cont> {
    tensor: Tensor<Cont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

tensor_traits!(FunctionalPackingKeyswitchKey);

impl<Scalar> FunctionalPackingKeyswitchKey<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a private functional packing keyswitching key whose masks and bodies are all
    /// `value`.
    ///
    /// # Note
    ///
    /// This function does *not* generate a private functional packing keyswitching key , but
    /// merely allocates a container of the right size.
    /// See [`FunctionalPackingKeyswitchKey::fill_with_functional_keyswitch_key`] to fill the
    /// container with a proper functional keyswitching key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(
    ///     fpksk.decomposition_level_count(),
    ///     DecompositionLevelCount(10)
    /// );
    /// assert_eq!(fpksk.decomposition_base_log(), DecompositionBaseLog(16));
    /// assert_eq!(fpksk.output_glwe_key_dimension(), GlweDimension(2));
    /// assert_eq!(fpksk.input_lwe_key_dimension(), LweDimension(10));
    /// ```
    pub fn allocate(
        value: Scalar,
        decomp_size: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        input_dimension: LweDimension,
        output_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
    ) -> Self {
        FunctionalPackingKeyswitchKey {
            tensor: Tensor::from_container(vec![
                value;
                decomp_size.0
                    * output_dimension.to_glwe_size().0
                    * output_polynomial_size.0
                    * (input_dimension.0 + 1)
            ]),
            decomp_base_log,
            decomp_level_count: decomp_size,
            output_glwe_size: output_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }
}

impl<Cont> FunctionalPackingKeyswitchKey<Cont> {
    /// Creates a private functional packing keyswitching key from a container.
    ///
    /// # Notes
    ///
    /// This method does not create a private functional packing keyswitch key, but merely wraps
    /// the container in the proper type. It assumes that either the container already contains a
    /// proper functional keyswitching key, or that
    /// [`FunctionalPackingKeyswitchKey::fill_with_functional_keyswitch_key`] will be called right
    /// after.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let input_size = LweDimension(200);
    /// let output_size = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_log_base = DecompositionBaseLog(7);
    /// let decomp_level_count = DecompositionLevelCount(4);
    ///
    /// let fpksk = FunctionalPackingKeyswitchKey::from_container(
    ///     vec![
    ///         0 as u8;
    ///         (input_size.0 + 1) * (output_size.0 + 1) * polynomial_size.0 * decomp_level_count.0
    ///     ],
    ///     decomp_log_base,
    ///     decomp_level_count,
    ///     output_size,
    ///     polynomial_size,
    /// );
    ///
    /// assert_eq!(
    ///     fpksk.decomposition_level_count(),
    ///     DecompositionLevelCount(4)
    /// );
    /// assert_eq!(fpksk.decomposition_base_log(), DecompositionBaseLog(7));
    /// assert_eq!(fpksk.output_glwe_key_dimension(), GlweDimension(2));
    /// assert_eq!(fpksk.input_lwe_key_dimension(), LweDimension(200));
    /// ```
    pub fn from_container(
        cont: Cont,
        decomp_base_log: DecompositionBaseLog,
        decomp_size: DecompositionLevelCount,
        output_glwe_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
    ) -> FunctionalPackingKeyswitchKey<Cont>
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => output_glwe_dimension.to_glwe_size().0 * output_polynomial_size.0, decomp_size.0);
        FunctionalPackingKeyswitchKey {
            tensor,
            decomp_base_log,
            decomp_level_count: decomp_size,
            output_glwe_size: output_glwe_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }

    /// Returns the dimension of the output GLWE key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(fpksk.output_glwe_key_dimension(), GlweDimension(2));
    /// ```
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Returns the size of the polynomials composing the GLWE ciphertext
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    ///     PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(fpksk.output_polynomial_size(), PolynomialSize(256));
    /// ```
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Returns the dimension of the input LWE key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(fpksk.input_lwe_key_dimension(), LweDimension(10));
    /// ```
    pub fn input_lwe_key_dimension(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(
            self.as_tensor().len()
                / (self.output_glwe_size.0
                    * self.output_polynomial_size.0
                    * self.decomp_level_count.0)
                - 1,
        )
    }

    /// Returns the number of levels used for the decomposition of the input key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(
    ///     fpksk.decomposition_level_count(),
    ///     DecompositionLevelCount(10)
    /// );
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        self.decomp_level_count
    }

    /// Returns the logarithm of the base used for the decomposition of the input key bits.
    ///
    /// Indeed, the basis used is always of the form $2^b$. This function returns $b$.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::*;
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(fpksk.decomposition_base_log(), DecompositionBaseLog(16));
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog
    where
        Self: AsRefTensor,
    {
        self.decomp_base_log
    }

    /// Fills the current private functional keyswitch key container with an actual
    /// functional keyswitching key constructed from an input and an output key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_commons::dispersion::LogStandardDev;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    ///     PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
    /// use concrete_core::backends::core::private::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use concrete_core::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use concrete_core::backends::core::private::crypto::*;
    /// use concrete_core::backends::core::private::math::polynomial::Polynomial;
    /// use concrete_core::backends::core::private::math::tensor::AsRefTensor;
    ///
    /// let input_size = LweDimension(10);
    /// let output_size = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_log_base = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let cipher_size = LweSize(55);
    /// let mut secret_generator = SecretRandomGenerator::new(None);
    /// let mut encryption_generator = EncryptionRandomGenerator::new(None);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_size, polynomial_size, &mut secret_generator);
    ///
    /// let mut fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u32,
    ///     decomp_level_count,
    ///     decomp_log_base,
    ///     input_size,
    ///     output_size,
    ///     polynomial_size,
    /// );
    /// fpksk.fill_with_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut encryption_generator,
    ///     |x| x,
    ///     &Polynomial::allocate(1 as u32, output_key.polynomial_size()),
    /// );
    ///
    /// assert!(!fpksk.as_tensor().iter().all(|a| *a == 0));
    /// ```
    pub fn fill_with_functional_packing_keyswitch_key<
        InKeyCont,
        OutKeyCont,
        Scalar,
        F: Fn(Scalar) -> Scalar,
        G,
    >(
        &mut self,
        input_lwe_key: &LweSecretKey<BinaryKeyKind, InKeyCont>,
        output_glwe_key: &GlweSecretKey<BinaryKeyKind, OutKeyCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<G>,
        f: F,
        polynomial: &Polynomial<Vec<Scalar>>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, InKeyCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, OutKeyCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        G: ByteRandomGenerator,
    {
        assert_eq!(
            polynomial.polynomial_size(),
            output_glwe_key.polynomial_size()
        );
        // TODO manage error

        // We instantiate a buffer
        let mut messages = PlaintextList::from_container(vec![
            <Self as AsMutTensor>::Element::ZERO;
            self.decomp_level_count.0
                * self.output_polynomial_size.0
        ]);
        // We retrieve decomposition arguments
        let decomp_level_count = self.decomp_level_count;
        let decomp_base_log = self.decomp_base_log;
        let polynomial_size = self.output_polynomial_size;

        let mut input_key_bit = input_lwe_key.as_tensor().as_slice().to_vec();

        //add minus one for the function which will be applied to the decomposed body
        // ( Scalar::MAX = -Scalar::ONE
        input_key_bit.push(Scalar::MAX);

        // loop over the before key blocks
        for (&input_key_bit, keyswitch_key_block) in
            input_key_bit.iter().zip(self.bit_decomp_iter_mut())
        {
            // We reset the buffer
            messages
                .as_mut_tensor()
                .fill_with_element(<Self as AsMutTensor>::Element::ZERO);

            // We fill the buffer with the powers of the key bits
            for (level, mut message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .zip(messages.sublist_iter_mut(PlaintextCount(polynomial_size.0)))
            {
                message.as_mut_tensor().update_with_add_element_mul(
                    polynomial.as_tensor(),
                    DecompositionTerm::new(
                        level,
                        decomp_base_log,
                        f(Scalar::ONE).wrapping_mul(input_key_bit),
                    )
                    .to_recomposition_summand(),
                );
            }

            // We encrypt the buffer
            output_glwe_key.encrypt_glwe_list(
                &mut keyswitch_key_block.into_glwe_list(),
                &messages,
                noise_parameters,
                generator,
            );
        }
    }

    /// Iterates over borrowed `LweKeyBitDecomposition` elements.
    ///
    /// One `LweKeyBitDecomposition` being a set of LWE ciphertexts, encrypting under the output
    /// key, the $l$ levels of the signed decomposition of a single bit of the input key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use concrete_core::backends::core::private::crypto::{*, glwe::FunctionalPackingKeyswitchKey};
    /// use concrete_commons::parameters::{DecompositionLevelCount, DecompositionBaseLog,
    /// GlweDimension, LweDimension, PolynomialSize};
    /// let fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(15),
    ///     GlweDimension(20),
    ///     PolynomialSize(256)
    /// );
    /// for decomp in fpksk.bit_decomp_iter() {
    ///     assert_eq!(decomp.lwe_size(), fpksk.lwe_size());
    ///     assert_eq!(decomp.count().0, 10);
    /// }
    /// assert_eq!(fpksk.bit_decomp_iter().count(), 15 + 1);
    /// ```
    pub(crate) fn bit_decomp_iter(
        &self,
    ) -> impl Iterator<Item = LweKeyBitDecomposition<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_tensor().subtensor_iter(size).map(move |sub| {
            LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
        })
    }

    /// Iterates over mutably borrowed `LweKeyBitDecomposition` elements.
    ///
    /// One `LweKeyBitDecomposition` being a set of LWE ciphertexts, encrypting under the output
    /// key, the $l$ levels of the signed decomposition of a single bit of the input key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use concrete_core::backends::core::private::crypto::{*, glwe::FunctionalPackingKeyswitchKey};
    /// use concrete_core::backends::core::private::math::tensor::{AsRefTensor, AsMutTensor};
    /// use concrete_commons::parameters::{DecompositionLevelCount, DecompositionBaseLog,
    /// GlweDimension, LweDimension, PolynomialSize};
    /// let mut fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(15),
    ///     GlweDimension(20),
    ///     PolynomialSize(256)
    /// );
    /// for mut decomp in fpksk.bit_decomp_iter_mut() {
    ///     for mut ciphertext in decomp.ciphertext_iter_mut() {
    ///         ciphertext.as_mut_tensor().fill_with_element(0);
    ///     }
    /// }
    /// assert!(fpksk.as_tensor().iter().all(|a| *a == 0));
    /// assert_eq!(fpksk.bit_decomp_iter_mut().count(), 15 + 1);
    /// ```
    pub(crate) fn bit_decomp_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = LweKeyBitDecomposition<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let chunks_size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |sub| {
                LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
            })
    }

    /// Keyswitches a single LWE ciphertext into a GLWE
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::dispersion::LogStandardDev;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::encoding::*;
    /// use concrete_core::backends::core::private::crypto::glwe::*;
    /// use concrete_core::backends::core::private::crypto::lwe::*;
    /// use concrete_core::backends::core::private::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use concrete_core::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use concrete_core::backends::core::private::crypto::*;
    /// use concrete_core::backends::core::private::math::polynomial::Polynomial;
    /// use concrete_core::backends::core::private::math::tensor::AsRefTensor;
    ///
    /// let input_size = LweDimension(1024);
    /// let output_size = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_log_base = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(8);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let mut secret_generator = SecretRandomGenerator::new(None);
    /// let mut encryption_generator = EncryptionRandomGenerator::new(None);
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_size, polynomial_size, &mut secret_generator);
    ///
    /// let mut fpksk = FunctionalPackingKeyswitchKey::allocate(
    ///     0 as u64,
    ///     decomp_level_count,
    ///     decomp_log_base,
    ///     input_size,
    ///     output_size,
    ///     polynomial_size,
    /// );
    /// fpksk.fill_with_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut encryption_generator,
    ///     |x| x,
    ///     &Polynomial::allocate(1 as u64, PolynomialSize(256)),
    /// );
    ///
    /// let plaintext: Plaintext<u64> = Plaintext(1432154329994324);
    /// let mut ciphertext = LweCiphertext::allocate(0. as u64, LweSize(1025));
    /// let mut switched_ciphertext =
    ///     GlweCiphertext::allocate(0. as u64, PolynomialSize(256), GlweSize(3));
    /// input_key.encrypt_lwe(
    ///     &mut ciphertext,
    ///     &plaintext,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    ///
    /// fpksk.functional_keyswitch_ciphertext(&mut switched_ciphertext, &ciphertext);
    ///
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u64; 256]);
    /// output_key.decrypt_glwe(&mut decrypted, &switched_ciphertext);
    /// ```
    pub fn functional_keyswitch_ciphertext<InCont, OutCont, Scalar>(
        &self,
        after: &mut GlweCiphertext<OutCont>,
        before: &LweCiphertext<InCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        LweCiphertext<InCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        ck_dim_eq!(self.input_lwe_key_dimension().0  => before.lwe_size().to_lwe_dimension().0 );
        ck_dim_eq!(self.output_glwe_key_dimension().0 => after.size().to_glwe_dimension().0);

        // We reset the output
        after.as_mut_tensor().fill_with(|| Scalar::ZERO);

        // We copy the body
        //*after.get_mut_body().tensor.as_mut_tensor().first_mut() = before.get_body().0;

        // We allocate a buffer to hold the decomposition.
        //  let mut decomp = Tensor::allocate(Scalar::ZERO, self.decomp_level_count.0);

        // We instantiate a decomposer
        let decomposer = SignedDecomposer::new(self.decomp_base_log, self.decomp_level_count);

        for (block, input_lwe) in self.bit_decomp_iter().zip(before.as_tensor().iter()) {
            // We decompose
            let rounded = decomposer.closest_representable(*input_lwe);
            let decomp = decomposer.decompose(rounded);

            //torus_small_sign_decompose(decomp.as_mut_slice(), rounded, self.decomp_base_log.0);

            // Loop over the number of levels:
            // We compute the multiplication of a ciphertext from the keyswitching key with a
            // piece of the decomposition and subtract it to the buffer
            for (level_key_cipher, decomposed) in block
                .as_tensor()
                .subtensor_iter(self.output_glwe_size.0 * self.output_polynomial_size.0)
                .rev()
                .zip(decomp)
            {
                after
                    .as_mut_tensor()
                    .update_with_wrapping_sub_element_mul(&level_key_cipher, decomposed.value());
            }
        }
    }

    /// Packs several LweCiphertext into a single GlweCiphertext
    /// with a functional keyswitch technique
    pub fn functional_packing_keyswitch<InCont, OutCont, Scalar>(
        &self,
        output: &mut GlweCiphertext<OutCont>,
        input: &LweList<InCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweList<InCont>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        OutCont: Clone,
        Scalar: UnsignedTorus,
    {
        debug_assert!(input.count().0 <= output.polynomial_size().0);
        output.as_mut_tensor().fill_with_element(Scalar::ZERO);
        let mut buffer = output.clone();
        // for each ciphertext, call mono_key_switch
        for (degree, input_cipher) in input.ciphertext_iter().enumerate() {
            self.functional_keyswitch_ciphertext(&mut buffer, &input_cipher);
            buffer
                .as_mut_polynomial_list()
                .polynomial_iter_mut()
                .for_each(|mut poly| {
                    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(degree))
                });
            output
                .as_mut_tensor()
                .update_with_wrapping_add(buffer.as_tensor());
        }
    }
}
