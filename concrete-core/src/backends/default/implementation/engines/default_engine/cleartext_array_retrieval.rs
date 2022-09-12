use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{CleartextArray32, CleartextArray64};
use crate::commons::math::tensor::AsRefTensor;
use crate::prelude::CleartextArrayF64;
use crate::specification::engines::{CleartextArrayRetrievalEngine, CleartextArrayRetrievalError};

/// # Description:
/// Implementation of [`CleartextArrayRetrievalEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl CleartextArrayRetrievalEngine<CleartextArray32, u32> for DefaultEngine {
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
    /// let retrieved: Vec<u32> = engine.retrieve_cleartext_array(&cleartext_array)?;
    ///
    /// assert_eq!(retrieved[0], 3_u32);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext_array(
        &mut self,
        cleartext: &CleartextArray32,
    ) -> Result<Vec<u32>, CleartextArrayRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_array_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_array_unchecked(
        &mut self,
        cleartext: &CleartextArray32,
    ) -> Vec<u32> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}

/// # Description:
/// Implementation of [`CleartextArrayRetrievalEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl CleartextArrayRetrievalEngine<CleartextArray64, u64> for DefaultEngine {
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
    /// let retrieved: Vec<u64> = engine.retrieve_cleartext_array(&cleartext_array)?;
    ///
    /// assert_eq!(retrieved[0], 3_u64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext_array(
        &mut self,
        cleartext: &CleartextArray64,
    ) -> Result<Vec<u64>, CleartextArrayRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_array_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_array_unchecked(
        &mut self,
        cleartext: &CleartextArray64,
    ) -> Vec<u64> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}

/// # Description:
/// Implementation of [`CleartextArrayRetrievalEngine`] for [`DefaultEngine`] that operates on 64
/// bits floating point numbers.
impl CleartextArrayRetrievalEngine<CleartextArrayF64, f64> for DefaultEngine {
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
    /// let retrieved: Vec<f64> = engine.retrieve_cleartext_array(&cleartext_array)?;
    ///
    /// assert_eq!(retrieved[0], 3.0_f64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext_array(
        &mut self,
        cleartext: &CleartextArrayF64,
    ) -> Result<Vec<f64>, CleartextArrayRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_array_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_array_unchecked(
        &mut self,
        cleartext: &CleartextArrayF64,
    ) -> Vec<f64> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}
