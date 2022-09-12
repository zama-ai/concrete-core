use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{PlaintextArray32, PlaintextArray64};
use crate::commons::math::tensor::AsRefTensor;
use crate::specification::engines::{PlaintextArrayRetrievalEngine, PlaintextArrayRetrievalError};

/// # Description:
/// Implementation of [`PlaintextArrayRetrievalEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl PlaintextArrayRetrievalEngine<PlaintextArray32, u32> for DefaultEngine {
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
    /// let output: Vec<u32> = engine.retrieve_plaintext_array(&plaintext_array)?;
    /// #
    /// assert_eq!(output[0], 3_u32 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_plaintext_array(
        &mut self,
        plaintext: &PlaintextArray32,
    ) -> Result<Vec<u32>, PlaintextArrayRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_array_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_array_unchecked(
        &mut self,
        plaintext: &PlaintextArray32,
    ) -> Vec<u32> {
        plaintext.0.as_tensor().as_container().to_vec()
    }
}

/// # Description:
/// Implementation of [`PlaintextArrayRetrievalEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl PlaintextArrayRetrievalEngine<PlaintextArray64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// let output: Vec<u64> = engine.retrieve_plaintext_array(&plaintext_array)?;
    /// #
    /// assert_eq!(output[0], 3_u64 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_plaintext_array(
        &mut self,
        plaintext: &PlaintextArray64,
    ) -> Result<Vec<u64>, PlaintextArrayRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_array_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_array_unchecked(
        &mut self,
        plaintext: &PlaintextArray64,
    ) -> Vec<u64> {
        plaintext.0.as_tensor().as_container().to_vec()
    }
}
