use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextVector64, LweCiphertextVectorMutView64, LweCiphertextVectorView64,
};
use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::specification::engines::{
    LweCiphertextVectorCreationEngine, LweCiphertextVectorCreationError,
};
use concrete_commons::parameters::LweSize;

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextVector64`] that does not own its memory.
impl LweCiphertextVectorCreationEngine<Vec<u64>, LweCiphertextVector64> for DefaultEngine {
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
    /// let mut owned_container = vec![0_u64; lwe_size.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: LweCiphertextVector64 =
    ///     engine.create_lwe_ciphertext_vector(slice, lwe_size)?;
    /// engine.destroy(ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorCreationError<Self::EngineError>> {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
    ) -> LweCiphertextVector64 {
        LweCiphertextVector64(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextVectorView64`] that does not own its memory.
impl<'data> LweCiphertextVectorCreationEngine<&'data [u64], LweCiphertextVectorView64<'data>>
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
    /// let mut owned_container = vec![0_u64; lwe_size.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorView64 =
    ///     engine.create_lwe_ciphertext_vector(slice, lwe_size)?;
    /// engine.destroy(ciphertext_vector_view)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
    ) -> Result<LweCiphertextVectorView64<'data>, LweCiphertextVectorCreationError<Self::EngineError>>
    {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
    ) -> LweCiphertextVectorView64<'data> {
        LweCiphertextVectorView64(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable [`LweCiphertextVectorMutView64`] that does not own its memory.
impl<'data> LweCiphertextVectorCreationEngine<&'data mut [u64], LweCiphertextVectorMutView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::LweSize;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let mut owned_container = vec![0_u64; lwe_size.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorMutView64 =
    ///     engine.create_lwe_ciphertext_vector(slice, lwe_size)?;
    /// engine.destroy(ciphertext_vector_view)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
    ) -> Result<
        LweCiphertextVectorMutView64<'data>,
        LweCiphertextVectorCreationError<Self::EngineError>,
    > {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_unchecked(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
    ) -> LweCiphertextVectorMutView64<'data> {
        LweCiphertextVectorMutView64(ImplLweList::from_container(container, lwe_size))
    }
}
