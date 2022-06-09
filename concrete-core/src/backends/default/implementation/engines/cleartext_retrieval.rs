use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{Cleartext32, Cleartext64};
use crate::specification::engines::{CleartextRetrievalEngine, CleartextRetrievalError};

/// # Description:
/// Implementation of [`CleartextRetrievalEngine`] for [`DefaultEngine`] that operates on 32 bits
/// integers.
impl CleartextRetrievalEngine<Cleartext32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u32 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new((
    ///     RandomGeneratorImplementation::Software,
    ///     Box::new(UnixSeeder::new(UNSAFE_SECRET)),
    /// ))?;
    /// let cleartext: Cleartext32 = engine.create_cleartext(&input)?;
    /// let output: u32 = engine.retrieve_cleartext(&cleartext)?;
    ///
    /// assert_eq!(output, 3_u32);
    /// engine.destroy(cleartext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext(
        &mut self,
        cleartext: &Cleartext32,
    ) -> Result<u32, CleartextRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_unchecked(&mut self, cleartext: &Cleartext32) -> u32 {
        cleartext.0 .0
    }
}

/// # Description:
/// Implementation of [`CleartextRetrievalEngine`] for [`DefaultEngine`] that operates on 64 bits
/// integers.
impl CleartextRetrievalEngine<Cleartext64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u64 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new((
    ///     RandomGeneratorImplementation::Software,
    ///     Box::new(UnixSeeder::new(UNSAFE_SECRET)),
    /// ))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext(&input)?;
    /// let output: u64 = engine.retrieve_cleartext(&cleartext)?;
    ///
    /// assert_eq!(output, 3_u64);
    /// engine.destroy(cleartext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext(
        &mut self,
        cleartext: &Cleartext64,
    ) -> Result<u64, CleartextRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_unchecked(&mut self, cleartext: &Cleartext64) -> u64 {
        cleartext.0 .0
    }
}
