use crate::backends::core::implementation::engines::CoreEngine;
use crate::prelude::{
    FunctionalPackingKeyswitchKey32, FunctionalPackingKeyswitchKey64, GlweCiphertext32,
    GlweCiphertext64, LweCiphertextVector32, LweCiphertextVector64,
};
use crate::specification::engines::{
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine,
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError,
};

/// # Description:
/// Implementation of
/// [`LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine`] for
/// [`CoreEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine<
        FunctionalPackingKeyswitchKey32,
        LweCiphertextVector32,
        GlweCiphertext32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let polynomial_size = PolynomialSize(256);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_vector = vec![3_u32 << 20, 256];
    ///
    /// let mut engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey32 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 =
    ///     engine.create_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    /// let val = vec![1_u32; output_key.polynomial_size().0];
    /// let polynomial: CleartextVector32 = engine.create_cleartext_vector(&val)?;
    /// let functional_packing_keyswitch_key = engine.create_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    ///     |x|x,
    ///     &polynomial,
    /// )?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input_vector)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_lwe_ciphertext_vector(&input_key, &plaintext_vector, noise)?;
    /// let mut ciphertext_output = engine.zero_encrypt_glwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_functional_packing_keyswitch_lwe_ciphertext_vector(
    ///     &mut ciphertext_output,
    ///     &ciphertext_vector,
    ///     &functional_packing_keyswitch_key,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_output.glwe_dimension(), output_glwe_dimension);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(functional_packing_keyswitch_key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(ciphertext_output)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &LweCiphertextVector32,
        ksk: &FunctionalPackingKeyswitchKey32,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    > {
        LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError
        ::perform_generic_checks(
            output, input, ksk,
        )?;
        unsafe {
            self.discard_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
                output, input, ksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &LweCiphertextVector32,
        ksk: &FunctionalPackingKeyswitchKey32,
    ) {
        ksk.0.functional_packing_keyswitch(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of
/// [`LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine`]
/// for
/// [`CoreEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchEngine<
        FunctionalPackingKeyswitchKey64,
        LweCiphertextVector64,
        GlweCiphertext64,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let polynomial_size = PolynomialSize(256);
    /// let noise = Variance(2_f64.powf(-25.));
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_vector = vec![3_u64 << 50, 256];
    ///
    /// let mut engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey64 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey64 =
    ///     engine.create_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    /// let val = vec![1_u64; output_key.polynomial_size().0];
    /// let polynomial: CleartextVector64 = engine.create_cleartext_vector(&val)?;
    /// let functional_packing_keyswitch_key = engine.create_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    ///     |x|x,
    ///     &polynomial,
    /// )?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input_vector)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_lwe_ciphertext_vector(&input_key, &plaintext_vector, noise)?;
    /// let mut ciphertext_output = engine.zero_encrypt_glwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_functional_packing_keyswitch_lwe_ciphertext_vector(
    ///     &mut ciphertext_output,
    ///     &ciphertext_vector,
    ///     &functional_packing_keyswitch_key,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_output.glwe_dimension(), output_glwe_dimension);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(functional_packing_keyswitch_key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(ciphertext_output)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &LweCiphertextVector64,
        ksk: &FunctionalPackingKeyswitchKey64,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    > {
        LweCiphertextVectorGlweCiphertextDiscardingFunctionalPackingKeyswitchError
        ::perform_generic_checks(
            output, input, ksk,
        )?;
        unsafe {
            self.discard_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
                output, input, ksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &LweCiphertextVector64,
        ksk: &FunctionalPackingKeyswitchKey64,
    ) {
        ksk.0.functional_packing_keyswitch(&mut output.0, &input.0);
    }
}
