use crate::backends::default::implementation::engines::DefaultEngine;
use crate::prelude::{
    GlweCiphertext32, GlweCiphertext64, LweCiphertextArray32, LweCiphertextArray64,
    LwePrivateFunctionalPackingKeyswitchKey32, LwePrivateFunctionalPackingKeyswitchKey64,
};
use crate::specification::engines::{
    LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine,
    LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError,
};

/// # Description:
/// Implementation of
/// [`LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
        LwePrivateFunctionalPackingKeyswitchKey32,
        LweCiphertextArray32,
        GlweCiphertext32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_array = vec![3_u32 << 20, 256];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    /// let val = vec![1_u32; output_key.polynomial_size().0];
    /// let polynomial: CleartextArray32 = engine.create_cleartext_array_from(&val)?;
    /// let private_functional_packing_keyswitch_key = engine
    ///     .generate_new_lwe_private_functional_packing_keyswitch_key(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_level_count,
    ///         decomposition_base_log,
    ///         StandardDev(noise.get_standard_dev()),
    ///         &|x| x,
    ///         &polynomial,
    ///     )?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input_array)?;
    /// let ciphertext_array =
    ///     engine.encrypt_lwe_ciphertext_array(&input_key, &plaintext_array, noise)?;
    /// let mut ciphertext_output = engine.zero_encrypt_glwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_private_functional_packing_keyswitch_lwe_ciphertext_array(
    ///     &mut ciphertext_output,
    ///     &ciphertext_array,
    ///     &private_functional_packing_keyswitch_key,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_output.glwe_dimension(), output_glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_private_functional_packing_keyswitch_lwe_ciphertext_array(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &LweCiphertextArray32,
        pfpksk: &LwePrivateFunctionalPackingKeyswitchKey32,
    ) -> Result<
        (),
        LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    > {
        LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError
        ::perform_generic_checks(
            output, input, pfpksk,
        )?;
        unsafe {
            self.discard_private_functional_packing_keyswitch_lwe_ciphertext_array_unchecked(
                output, input, pfpksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_private_functional_packing_keyswitch_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &LweCiphertextArray32,
        pfpksk: &LwePrivateFunctionalPackingKeyswitchKey32,
    ) {
        pfpksk
            .0
            .private_functional_packing_keyswitch(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of
/// [`LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
        LwePrivateFunctionalPackingKeyswitchKey64,
        LweCiphertextArray64,
        GlweCiphertext64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_array = vec![3_u64 << 50, 256];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(output_glwe_dimension, polynomial_size)?;
    /// let val = vec![1_u64; output_key.polynomial_size().0];
    /// let polynomial: CleartextArray64 = engine.create_cleartext_array_from(&val)?;
    /// let private_functional_packing_keyswitch_key = engine
    ///     .generate_new_lwe_private_functional_packing_keyswitch_key(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_level_count,
    ///         decomposition_base_log,
    ///         StandardDev(noise.get_standard_dev()),
    ///         &|x| x,
    ///         &polynomial,
    ///     )?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input_array)?;
    /// let ciphertext_array =
    ///     engine.encrypt_lwe_ciphertext_array(&input_key, &plaintext_array, noise)?;
    /// let mut ciphertext_output = engine.zero_encrypt_glwe_ciphertext(&output_key, noise)?;
    ///
    /// engine.discard_private_functional_packing_keyswitch_lwe_ciphertext_array(
    ///     &mut ciphertext_output,
    ///     &ciphertext_array,
    ///     &private_functional_packing_keyswitch_key,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_output.glwe_dimension(), output_glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_private_functional_packing_keyswitch_lwe_ciphertext_array(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &LweCiphertextArray64,
        pfpksk: &LwePrivateFunctionalPackingKeyswitchKey64,
    ) -> Result<
        (),
        LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    > {
        LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError
        ::perform_generic_checks(
            output, input, pfpksk,
        )?;
        unsafe {
            self.discard_private_functional_packing_keyswitch_lwe_ciphertext_array_unchecked(
                output, input, pfpksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_private_functional_packing_keyswitch_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &LweCiphertextArray64,
        pfpksk: &LwePrivateFunctionalPackingKeyswitchKey64,
    ) {
        pfpksk
            .0
            .private_functional_packing_keyswitch(&mut output.0, &input.0);
    }
}
