use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Plaintext32, Plaintext64};
use crate::commons::crypto::encoding::Plaintext as ImplPlaintext;
use crate::specification::engines::{PlaintextCreationEngine, PlaintextCreationError};

/// # Description:
/// Implementation of [`PlaintextCreationEngine`] for [`CoreEngine`] that operates on
/// 32 bits integers.
impl PlaintextCreationEngine<u32, Plaintext32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = CoreEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext(&input)?;
    /// engine.destroy(plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_plaintext(
        &mut self,
        input: &u32,
    ) -> Result<Plaintext32, PlaintextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_plaintext_unchecked(input) })
    }

    unsafe fn create_plaintext_unchecked(&mut self, input: &u32) -> Plaintext32 {
        Plaintext32(ImplPlaintext(*input))
    }
}

/// # Description:
/// Implementation of [`PlaintextCreationEngine`] for [`CoreEngine`] that operates on
/// 64 bits integers.
impl PlaintextCreationEngine<u64, Plaintext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = CoreEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext(&input)?;
    /// engine.destroy(plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_plaintext(
        &mut self,
        input: &u64,
    ) -> Result<Plaintext64, PlaintextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_plaintext_unchecked(input) })
    }

    unsafe fn create_plaintext_unchecked(&mut self, input: &u64) -> Plaintext64 {
        Plaintext64(ImplPlaintext(*input))
    }
}
