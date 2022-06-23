use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextPlaintextFusingAdditionEngine, LweCiphertextPlaintextFusingAdditionError,
};

/// # Description:
/// Implementation of [`LweCiphertextPlaintextFusingAdditionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextPlaintextFusingAdditionEngine<LweCiphertext32, Plaintext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = 3_u32 << 20;
    /// let input_2 = 5_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_1 = engine.create_plaintext(&input_1)?;
    /// let plaintext_2 = engine.create_plaintext(&input_2)?;
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext_1, noise)?;
    ///
    /// engine.fuse_add_lwe_ciphertext_plaintext(&mut ciphertext, &plaintext_2)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_1)?;
    /// engine.destroy(plaintext_2)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) -> Result<(), LweCiphertextPlaintextFusingAdditionError<Self::EngineError>> {
        unsafe { self.fuse_add_lwe_ciphertext_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) {
        output.0.get_mut_body().0 = output.0.get_body().0.wrapping_add(input.0 .0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextPlaintextFusingAdditionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextPlaintextFusingAdditionEngine<LweCiphertext64, Plaintext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 40 bits)
    /// let input_1 = 3_u64 << 40;
    /// let input_2 = 5_u64 << 40;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_1 = engine.create_plaintext(&input_1)?;
    /// let plaintext_2 = engine.create_plaintext(&input_2)?;
    /// let mut ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext_1, noise)?;
    ///
    /// engine.fuse_add_lwe_ciphertext_plaintext(&mut ciphertext, &plaintext_2)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_1)?;
    /// engine.destroy(plaintext_2)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) -> Result<(), LweCiphertextPlaintextFusingAdditionError<Self::EngineError>> {
        unsafe { self.fuse_add_lwe_ciphertext_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn fuse_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) {
        output.0.get_mut_body().0 = output.0.get_body().0.wrapping_add(input.0 .0);
    }
}
