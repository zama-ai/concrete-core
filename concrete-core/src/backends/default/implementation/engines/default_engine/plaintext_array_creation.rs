use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{PlaintextArray32, PlaintextArray64};
use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::specification::engines::{PlaintextArrayCreationEngine, PlaintextArrayCreationError};

/// # Description:
/// Implementation of [`PlaintextArrayCreationEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl PlaintextArrayCreationEngine<u32, PlaintextArray32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    /// #
    /// assert_eq!(plaintext_array.plaintext_count(), PlaintextCount(3));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_plaintext_array_from(
        &mut self,
        input: &[u32],
    ) -> Result<PlaintextArray32, PlaintextArrayCreationError<Self::EngineError>> {
        if input.is_empty() {
            return Err(PlaintextArrayCreationError::EmptyInput);
        }
        Ok(unsafe { self.create_plaintext_array_from_unchecked(input) })
    }

    unsafe fn create_plaintext_array_from_unchecked(&mut self, input: &[u32]) -> PlaintextArray32 {
        PlaintextArray32(ImplPlaintextList::from_container(input.to_vec()))
    }
}

/// # Description:
/// Implementation of [`PlaintextArrayCreationEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl PlaintextArrayCreationEngine<u64, PlaintextArray64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// #
    /// assert_eq!(plaintext_array.plaintext_count(), PlaintextCount(3));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_plaintext_array_from(
        &mut self,
        input: &[u64],
    ) -> Result<PlaintextArray64, PlaintextArrayCreationError<Self::EngineError>> {
        if input.is_empty() {
            return Err(PlaintextArrayCreationError::EmptyInput);
        }
        Ok(unsafe { self.create_plaintext_array_from_unchecked(input) })
    }

    unsafe fn create_plaintext_array_from_unchecked(&mut self, input: &[u64]) -> PlaintextArray64 {
        PlaintextArray64(ImplPlaintextList::from_container(input.to_vec()))
    }
}
