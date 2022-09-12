use crate::prelude::PlaintextCount;

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArray32, LweCiphertextArray64, LweSecretKey32, LweSecretKey64, PlaintextArray32,
    PlaintextArray64,
};
use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::prelude::{LweCiphertextArrayView32, LweCiphertextArrayView64};
use crate::specification::engines::{
    LweCiphertextArrayDecryptionEngine, LweCiphertextArrayDecryptionError,
};
use crate::specification::entities::LweCiphertextArrayEntity;

/// # Description:
/// Implementation of [`LweCiphertextArrayDecryptionEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweCiphertextArrayDecryptionEngine<LweSecretKey32, LweCiphertextArray32, PlaintextArray32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, PlaintextCount, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext_array: LweCiphertextArray32 =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let decrypted_plaintext_array = engine.decrypt_lwe_ciphertext_array(&key, &ciphertext_array)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_array.plaintext_count(),
    ///     PlaintextCount(18)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextArray32,
    ) -> Result<PlaintextArray32, LweCiphertextArrayDecryptionError<Self::EngineError>> {
        LweCiphertextArrayDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_array_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextArray32,
    ) -> PlaintextArray32 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u32, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextArray32(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDecryptionEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweCiphertextArrayDecryptionEngine<LweSecretKey64, LweCiphertextArray64, PlaintextArray64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, PlaintextCount, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext_array: LweCiphertextArray64 =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let decrypted_plaintext_array = engine.decrypt_lwe_ciphertext_array(&key, &ciphertext_array)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_array.plaintext_count(),
    ///     PlaintextCount(18)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextArray64,
    ) -> Result<PlaintextArray64, LweCiphertextArrayDecryptionError<Self::EngineError>> {
        LweCiphertextArrayDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_array_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextArray64,
    ) -> PlaintextArray64 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u64, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextArray64(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextArrayDecryptionEngine<
        LweSecretKey32,
        LweCiphertextArrayView32<'_>,
        PlaintextArray32,
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
    /// let lwe_count = LweCiphertextCount(18);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut raw_ciphertext_array = vec![0_u32; key.lwe_dimension().to_lwe_size().0 * lwe_count.0];
    /// let mut ciphertext_array_view: LweCiphertextArrayMutView32 = engine
    ///     .create_lwe_ciphertext_array_from(
    ///         &mut raw_ciphertext_array[..],
    ///         lwe_dimension.to_lwe_size(),
    ///     )?;
    /// engine.discard_encrypt_lwe_ciphertext_array(
    ///     &key,
    ///     &mut ciphertext_array_view,
    ///     &plaintext_array,
    ///     noise,
    /// )?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_array =
    ///     engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array_view)?;
    /// let ciphertext_array_view: LweCiphertextArrayView32 = engine
    ///     .create_lwe_ciphertext_array_from(&raw_ciphertext_array[..], lwe_dimension.to_lwe_size())?;
    ///
    /// let decrypted_plaintext_array =
    ///     engine.decrypt_lwe_ciphertext_array(&key, &ciphertext_array_view)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_array.plaintext_count(),
    ///     PlaintextCount(lwe_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextArrayView32<'_>,
    ) -> Result<PlaintextArray32, LweCiphertextArrayDecryptionError<Self::EngineError>> {
        LweCiphertextArrayDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_array_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &LweCiphertextArrayView32<'_>,
    ) -> PlaintextArray32 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u32, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextArray32(plaintext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextArrayDecryptionEngine<
        LweSecretKey64,
        LweCiphertextArrayView64<'_>,
        PlaintextArray64,
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
    /// let lwe_count = LweCiphertextCount(18);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut raw_ciphertext_array = vec![0_u64; key.lwe_dimension().to_lwe_size().0 * lwe_count.0];
    /// let mut ciphertext_array_view: LweCiphertextArrayMutView64 = engine
    ///     .create_lwe_ciphertext_array_from(
    ///         &mut raw_ciphertext_array[..],
    ///         lwe_dimension.to_lwe_size(),
    ///     )?;
    /// engine.discard_encrypt_lwe_ciphertext_array(
    ///     &key,
    ///     &mut ciphertext_array_view,
    ///     &plaintext_array,
    ///     noise,
    /// )?;
    ///
    /// // Convert MutView to View
    /// let raw_ciphertext_array =
    ///     engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array_view)?;
    /// let ciphertext_array_view: LweCiphertextArrayView64 = engine
    ///     .create_lwe_ciphertext_array_from(&raw_ciphertext_array[..], lwe_dimension.to_lwe_size())?;
    ///
    /// let decrypted_plaintext_array =
    ///     engine.decrypt_lwe_ciphertext_array(&key, &ciphertext_array_view)?;
    ///
    /// assert_eq!(
    ///     decrypted_plaintext_array.plaintext_count(),
    ///     PlaintextCount(lwe_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextArrayView64<'_>,
    ) -> Result<PlaintextArray64, LweCiphertextArrayDecryptionError<Self::EngineError>> {
        LweCiphertextArrayDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_lwe_ciphertext_array_unchecked(key, input) })
    }

    unsafe fn decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextArrayView64<'_>,
    ) -> PlaintextArray64 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u64, PlaintextCount(input.lwe_ciphertext_count().0));
        key.0.decrypt_lwe_list(&mut plaintext, &input.0);
        PlaintextArray64(plaintext)
    }
}
