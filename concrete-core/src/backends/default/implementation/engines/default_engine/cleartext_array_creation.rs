use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{CleartextArray32, CleartextArray64};
use crate::commons::crypto::encoding::CleartextList as ImplCleartextList;
use crate::prelude::CleartextArrayF64;
use crate::specification::engines::{CleartextArrayCreationEngine, CleartextArrayCreationError};

/// # Description:
/// Implementation of [`CleartextArrayCreationEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl CleartextArrayCreationEngine<u32, CleartextArray32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u32; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArray32 = engine.create_cleartext_array_from(&input)?;
    /// #
    /// assert_eq!(cleartext_array.cleartext_count(), CleartextCount(100));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_array_from(
        &mut self,
        input: &[u32],
    ) -> Result<CleartextArray32, CleartextArrayCreationError<Self::EngineError>> {
        CleartextArrayCreationError::perform_generic_checks(input)?;
        Ok(unsafe { self.create_cleartext_array_from_unchecked(input) })
    }

    unsafe fn create_cleartext_array_from_unchecked(&mut self, input: &[u32]) -> CleartextArray32 {
        CleartextArray32(ImplCleartextList::from_container(input.to_vec()))
    }
}

/// # Description:
/// Implementation of [`CleartextArrayCreationEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl CleartextArrayCreationEngine<u64, CleartextArray64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArray64 = engine.create_cleartext_array_from(&input)?;
    /// #
    /// assert_eq!(cleartext_array.cleartext_count(), CleartextCount(100));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_array_from(
        &mut self,
        input: &[u64],
    ) -> Result<CleartextArray64, CleartextArrayCreationError<Self::EngineError>> {
        CleartextArrayCreationError::perform_generic_checks(input)?;
        Ok(unsafe { self.create_cleartext_array_from_unchecked(input) })
    }

    unsafe fn create_cleartext_array_from_unchecked(&mut self, input: &[u64]) -> CleartextArray64 {
        CleartextArray64(ImplCleartextList::from_container(input.to_vec()))
    }
}

/// # Description:
/// Implementation of [`CleartextArrayCreationEngine`] for [`DefaultEngine`] that operates on 64
/// bits floating point numbers.
impl CleartextArrayCreationEngine<f64, CleartextArrayF64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3.0_f64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArrayF64 = engine.create_cleartext_array_from(&input)?;
    /// #
    /// assert_eq!(cleartext_array.cleartext_count(), CleartextCount(100));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_array_from(
        &mut self,
        values: &[f64],
    ) -> Result<CleartextArrayF64, CleartextArrayCreationError<Self::EngineError>> {
        CleartextArrayCreationError::perform_generic_checks(values)?;
        Ok(unsafe { self.create_cleartext_array_from_unchecked(values) })
    }

    unsafe fn create_cleartext_array_from_unchecked(
        &mut self,
        values: &[f64],
    ) -> CleartextArrayF64 {
        CleartextArrayF64(ImplCleartextList::from_container(values.to_vec()))
    }
}
