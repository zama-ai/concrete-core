use crate::prelude::Variance;

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArray32, LweCiphertextArray64, LweSecretKey32, LweSecretKey64, PlaintextArray32,
    PlaintextArray64,
};
use crate::prelude::{LweCiphertextArrayMutView32, LweCiphertextArrayMutView64};
use crate::specification::engines::{
    LweCiphertextArrayDiscardingEncryptionEngine, LweCiphertextArrayDiscardingEncryptionError,
};

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextArrayDiscardingEncryptionEngine<
        LweSecretKey32,
        PlaintextArray32,
        LweCiphertextArray32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    /// let mut ciphertext_array: LweCiphertextArray32 =
    ///     engine.zero_encrypt_lwe_ciphertext_array(&key, noise, LweCiphertextCount(3))?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_array(
    ///     &key,
    ///     &mut ciphertext_array,
    ///     &plaintext_array,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_array.lwe_ciphertext_count(),
    /// #     LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextArray32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> Result<(), LweCiphertextArrayDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_array_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextArray32,
        input: &PlaintextArray32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextArrayDiscardingEncryptionEngine<
        LweSecretKey64,
        PlaintextArray64,
        LweCiphertextArray64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// let mut ciphertext_array: LweCiphertextArray64 =
    ///     engine.zero_encrypt_lwe_ciphertext_array(&key, noise, LweCiphertextCount(3))?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_array(
    ///     &key,
    ///     &mut ciphertext_array,
    ///     &plaintext_array,
    ///     noise,
    /// );
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_array.lwe_ciphertext_count(),
    /// #     LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextArray64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> Result<(), LweCiphertextArrayDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_array_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextArray64,
        input: &PlaintextArray64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextArrayDiscardingEncryptionEngine<
        LweSecretKey32,
        PlaintextArray32,
        LweCiphertextArrayMutView32<'_>,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut output_ciphertext_array_container = vec![0_32; lwe_dimension.to_lwe_size().0 *
    ///     lwe_count.0];
    /// let mut ciphertext_array: LweCiphertextArrayMutView32 =
    ///     engine.create_lwe_ciphertext_array_from(&mut output_ciphertext_array_container[..],
    ///     lwe_dimension.to_lwe_size())?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_array(&key, &mut ciphertext_array,
    ///     &plaintext_array, noise)?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_array.lwe_ciphertext_count(),
    /// #     lwe_count,
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextArrayMutView32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> Result<(), LweCiphertextArrayDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_array_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextArrayMutView32,
        input: &PlaintextArray32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextArrayDiscardingEncryptionEngine<
        LweSecretKey64,
        PlaintextArray64,
        LweCiphertextArrayMutView64<'_>,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut output_ciphertext_array_container = vec![0_64; lwe_dimension.to_lwe_size().0 *
    ///     lwe_count.0];
    /// let mut ciphertext_array: LweCiphertextArrayMutView64 =
    ///     engine.create_lwe_ciphertext_array_from(&mut output_ciphertext_array_container[..],
    ///     lwe_dimension.to_lwe_size())?;
    ///
    /// engine.discard_encrypt_lwe_ciphertext_array(&key, &mut ciphertext_array,
    ///     &plaintext_array, noise)?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_array.lwe_ciphertext_count(),
    /// #     lwe_count,
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextArrayMutView64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> Result<(), LweCiphertextArrayDiscardingEncryptionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_lwe_ciphertext_array_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextArrayMutView64,
        input: &PlaintextArray64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
