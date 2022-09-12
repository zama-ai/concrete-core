use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{CleartextArray32, CleartextArray64};
use crate::commons::math::tensor::AsRefTensor;
use crate::prelude::CleartextArrayF64;
use crate::specification::engines::{
    CleartextArrayDiscardingRetrievalEngine, CleartextArrayDiscardingRetrievalError,
};

/// # Description:
/// Implementation of [`CleartextArrayDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl CleartextArrayDiscardingRetrievalEngine<CleartextArray32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u32; 100];
    /// let mut retrieved = vec![0_u32; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArray32 = engine.create_cleartext_array_from(&input)?;
    /// engine.discard_retrieve_cleartext_array(retrieved.as_mut_slice(), &cleartext_array)?;
    ///
    /// assert_eq!(retrieved[0], 3_u32);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext_array(
        &mut self,
        output: &mut [u32],
        input: &CleartextArray32,
    ) -> Result<(), CleartextArrayDiscardingRetrievalError<Self::EngineError>> {
        CleartextArrayDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_cleartext_array_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_array_unchecked(
        &mut self,
        output: &mut [u32],
        input: &CleartextArray32,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

/// # Description:
/// Implementation of [`CleartextArrayDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl CleartextArrayDiscardingRetrievalEngine<CleartextArray64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u64; 100];
    /// let mut retrieved = vec![0_u64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArray64 = engine.create_cleartext_array_from(&input)?;
    /// engine.discard_retrieve_cleartext_array(retrieved.as_mut_slice(), &cleartext_array)?;
    ///
    /// assert_eq!(retrieved[0], 3_u64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext_array(
        &mut self,
        output: &mut [u64],
        input: &CleartextArray64,
    ) -> Result<(), CleartextArrayDiscardingRetrievalError<Self::EngineError>> {
        CleartextArrayDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_cleartext_array_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_array_unchecked(
        &mut self,
        output: &mut [u64],
        input: &CleartextArray64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

/// # Description:
/// Implementation of [`CleartextArrayDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 64 bits floating point numbers.
impl CleartextArrayDiscardingRetrievalEngine<CleartextArrayF64, f64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3.0_f64; 100];
    /// let mut retrieved = vec![0.0_f64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArrayF64 = engine.create_cleartext_array_from(&input)?;
    /// engine.discard_retrieve_cleartext_array(retrieved.as_mut_slice(), &cleartext_array)?;
    ///
    /// assert_eq!(retrieved[0], 3.0_f64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext_array(
        &mut self,
        output: &mut [f64],
        input: &CleartextArrayF64,
    ) -> Result<(), CleartextArrayDiscardingRetrievalError<Self::EngineError>> {
        CleartextArrayDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_cleartext_array_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_array_unchecked(
        &mut self,
        output: &mut [f64],
        input: &CleartextArrayF64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}
