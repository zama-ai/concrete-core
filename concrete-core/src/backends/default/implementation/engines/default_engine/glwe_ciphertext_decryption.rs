use crate::prelude::PlaintextCount;

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextArray32,
    PlaintextArray64,
};
use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::specification::engines::{
    GlweCiphertextDecryptionEngine, GlweCiphertextDecryptionError,
};
use crate::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GlweCiphertextDecryptionEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl GlweCiphertextDecryptionEngine<GlweSecretKey32, GlweCiphertext32, PlaintextArray32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let decrypted_plaintext_array = engine.decrypt_glwe_ciphertext(&key, &ciphertext)?;
    /// #
    /// assert_eq!(
    /// #     decrypted_plaintext_array.plaintext_count(),
    /// #     plaintext_array.plaintext_count()
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        input: &GlweCiphertext32,
    ) -> Result<PlaintextArray32, GlweCiphertextDecryptionError<Self::EngineError>> {
        GlweCiphertextDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_glwe_ciphertext_unchecked(key, input) })
    }

    unsafe fn decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &GlweCiphertext32,
    ) -> PlaintextArray32 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u32, PlaintextCount(key.polynomial_size().0));
        key.0.decrypt_glwe(&mut plaintext, &input.0);
        PlaintextArray32(plaintext)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextDecryptionEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl GlweCiphertextDecryptionEngine<GlweSecretKey64, GlweCiphertext64, PlaintextArray64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let decrypted_plaintext_array = engine.decrypt_glwe_ciphertext(&key, &ciphertext)?;
    /// #
    /// assert_eq!(
    /// #     decrypted_plaintext_array.plaintext_count(),
    /// #     plaintext_array.plaintext_count()
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        input: &GlweCiphertext64,
    ) -> Result<PlaintextArray64, GlweCiphertextDecryptionError<Self::EngineError>> {
        GlweCiphertextDecryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.decrypt_glwe_ciphertext_unchecked(key, input) })
    }

    unsafe fn decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &GlweCiphertext64,
    ) -> PlaintextArray64 {
        let mut plaintext =
            ImplPlaintextList::allocate(0u64, PlaintextCount(key.polynomial_size().0));
        key.0.decrypt_glwe(&mut plaintext, &input.0);
        PlaintextArray64(plaintext)
    }
}
