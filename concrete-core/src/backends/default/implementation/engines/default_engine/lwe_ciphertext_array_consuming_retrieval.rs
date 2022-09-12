use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArray64, LweCiphertextArrayMutView64, LweCiphertextArrayView64,
};
use crate::commons::math::tensor::IntoTensor;
use crate::prelude::{LweCiphertextArray32, LweCiphertextArrayMutView32, LweCiphertextArrayView32};
use crate::specification::engines::{
    LweCiphertextArrayConsumingRetrievalEngine, LweCiphertextArrayConsumingRetrievalError,
};

/// # Description:
/// Implementation of [`LweCiphertextArrayConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextArray32`] consuming it in the process
impl LweCiphertextArrayConsumingRetrievalEngine<LweCiphertextArray32, Vec<u32>> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// use concrete_core::commons::crypto::lwe::LweCiphertext;
    /// let lwe_size = LweSize(128);
    /// let lwe_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array: LweCiphertextArray32 =
    ///     engine.create_lwe_ciphertext_array_from(owned_container, lwe_size)?;
    /// let retrieved_container = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: LweCiphertextArray32,
    ) -> Result<Vec<u32>, LweCiphertextArrayConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_array_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: LweCiphertextArray32,
    ) -> Vec<u32> {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextArray64`] consuming it in the process
impl LweCiphertextArrayConsumingRetrievalEngine<LweCiphertextArray64, Vec<u64>> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// use concrete_core::commons::crypto::lwe::LweCiphertext;
    /// let lwe_size = LweSize(128);
    /// let lwe_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array: LweCiphertextArray64 =
    ///     engine.create_lwe_ciphertext_array_from(owned_container, lwe_size)?;
    /// let retrieved_container = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: LweCiphertextArray64,
    ) -> Result<Vec<u64>, LweCiphertextArrayConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_array_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: LweCiphertextArray64,
    ) -> Vec<u64> {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextArrayView32`] consuming it in the process
impl<'data>
    LweCiphertextArrayConsumingRetrievalEngine<LweCiphertextArrayView32<'data>, &'data [u32]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayView32 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array_view)?;
    /// assert_eq!(slice, retrieved_slice);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: LweCiphertextArrayView32<'data>,
    ) -> Result<&'data [u32], LweCiphertextArrayConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_array_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: LweCiphertextArrayView32<'data>,
    ) -> &'data [u32] {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextArrayView64`] consuming it in the process
impl<'data>
    LweCiphertextArrayConsumingRetrievalEngine<LweCiphertextArrayView64<'data>, &'data [u64]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayView64 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array_view)?;
    /// assert_eq!(slice, retrieved_slice);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: LweCiphertextArrayView64<'data>,
    ) -> Result<&'data [u64], LweCiphertextArrayConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_array_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: LweCiphertextArrayView64<'data>,
    ) -> &'data [u64] {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextArrayMutView32`] consuming it in the process
impl<'data>
    LweCiphertextArrayConsumingRetrievalEngine<LweCiphertextArrayMutView32<'data>, &'data mut [u32]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &mut owned_container[..];
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayMutView32 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array_view)?;
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: LweCiphertextArrayMutView32<'data>,
    ) -> Result<&'data mut [u32], LweCiphertextArrayConsumingRetrievalError<Self::EngineError>>
    {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_array_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: LweCiphertextArrayMutView32<'data>,
    ) -> &'data mut [u32] {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextArrayMutView64`] consuming it in the process
impl<'data>
    LweCiphertextArrayConsumingRetrievalEngine<LweCiphertextArrayMutView64<'data>, &'data mut [u64]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &mut owned_container[..];
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayMutView64 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array_view)?;
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_array(
        &mut self,
        ciphertext: LweCiphertextArrayMutView64<'data>,
    ) -> Result<&'data mut [u64], LweCiphertextArrayConsumingRetrievalError<Self::EngineError>>
    {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_array_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_array_unchecked(
        &mut self,
        ciphertext: LweCiphertextArrayMutView64<'data>,
    ) -> &'data mut [u64] {
        ciphertext.0.into_tensor().into_container()
    }
}
