use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArrayMutView64, LweCiphertextArrayView64,
};
use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::prelude::{
    LweCiphertextArray32, LweCiphertextArray64, LweCiphertextArrayMutView32,
    LweCiphertextArrayView32, LweSize,
};
use crate::specification::engines::{
    LweCiphertextArrayCreationEngine, LweCiphertextArrayCreationError,
};

/// # Description:
/// Implementation of [`LweCiphertextArrayCreationEngine`] for [`DefaultEngine`] which returns a
/// [`LweCiphertextArray32`].
impl LweCiphertextArrayCreationEngine<Vec<u32>, LweCiphertextArray32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array: LweCiphertextArray32 =
    ///     engine.create_lwe_ciphertext_array_from(owned_container, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: Vec<u32>,
        lwe_size: LweSize,
    ) -> Result<LweCiphertextArray32, LweCiphertextArrayCreationError<Self::EngineError>> {
        LweCiphertextArrayCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_array_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: Vec<u32>,
        lwe_size: LweSize,
    ) -> LweCiphertextArray32 {
        LweCiphertextArray32(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayCreationEngine`] for [`DefaultEngine`] which returns a
/// [`LweCiphertextArray64`].
impl LweCiphertextArrayCreationEngine<Vec<u64>, LweCiphertextArray64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array: LweCiphertextArray64 =
    ///     engine.create_lwe_ciphertext_array_from(owned_container, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
    ) -> Result<LweCiphertextArray64, LweCiphertextArrayCreationError<Self::EngineError>> {
        LweCiphertextArrayCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_array_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
    ) -> LweCiphertextArray64 {
        LweCiphertextArray64(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextArrayView32`] that does not own its memory.
impl<'data> LweCiphertextArrayCreationEngine<&'data [u32], LweCiphertextArrayView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayView32 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: &'data [u32],
        lwe_size: LweSize,
    ) -> Result<LweCiphertextArrayView32<'data>, LweCiphertextArrayCreationError<Self::EngineError>>
    {
        LweCiphertextArrayCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_array_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: &'data [u32],
        lwe_size: LweSize,
    ) -> LweCiphertextArrayView32<'data> {
        LweCiphertextArrayView32(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable [`LweCiphertextArrayMutView32`] that does not own its memory.
impl<'data> LweCiphertextArrayCreationEngine<&'data mut [u32], LweCiphertextArrayMutView32<'data>>
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
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayMutView32 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: &'data mut [u32],
        lwe_size: LweSize,
    ) -> Result<
        LweCiphertextArrayMutView32<'data>,
        LweCiphertextArrayCreationError<Self::EngineError>,
    > {
        LweCiphertextArrayCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_array_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: &'data mut [u32],
        lwe_size: LweSize,
    ) -> LweCiphertextArrayMutView32<'data> {
        LweCiphertextArrayMutView32(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextArrayView64`] that does not own its memory.
impl<'data> LweCiphertextArrayCreationEngine<&'data [u64], LweCiphertextArrayView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayView64 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
    ) -> Result<LweCiphertextArrayView64<'data>, LweCiphertextArrayCreationError<Self::EngineError>>
    {
        LweCiphertextArrayCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_array_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
    ) -> LweCiphertextArrayView64<'data> {
        LweCiphertextArrayView64(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable [`LweCiphertextArrayMutView64`] that does not own its memory.
impl<'data> LweCiphertextArrayCreationEngine<&'data mut [u64], LweCiphertextArrayMutView64<'data>>
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
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_array_view: LweCiphertextArrayMutView64 =
    ///     engine.create_lwe_ciphertext_array_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_array_from(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
    ) -> Result<
        LweCiphertextArrayMutView64<'data>,
        LweCiphertextArrayCreationError<Self::EngineError>,
    > {
        LweCiphertextArrayCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_array_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_array_from_unchecked(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
    ) -> LweCiphertextArrayMutView64<'data> {
        LweCiphertextArrayMutView64(ImplLweList::from_container(container, lwe_size))
    }
}
