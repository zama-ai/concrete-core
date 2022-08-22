use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweBootstrapKey32, LweBootstrapKey64, LweBootstrapKeyMutView32, LweBootstrapKeyMutView64,
    LweBootstrapKeyView32, LweBootstrapKeyView64,
};
use crate::commons::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::specification::engines::{
    LweBootstrapKeyConstructionEngine, LweBootstrapKeyConstructionError,
};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};

impl LweBootstrapKeyConstructionEngine<Vec<u32>, LweBootstrapKey32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u32; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let lwe_bootstrap_key: LweBootstrapKey32 = engine.construct_lwe_bootstrap_key(
    ///     owned_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     base_log,
    ///     level,
    /// )?;
    ///
    /// # assert_eq!(lwe_dimension, lwe_bootstrap_key.input_lwe_dimension());
    /// # assert_eq!(glwe_size, lwe_bootstrap_key.glwe_dimension().to_glwe_size());
    /// # assert_eq!(polynomial_size, lwe_bootstrap_key.polynomial_size());
    /// # assert_eq!(level, lwe_bootstrap_key.decomposition_level_count());
    /// # assert_eq!(base_log, lwe_bootstrap_key.decomposition_base_log());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: Vec<u32>,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweBootstrapKey32, LweBootstrapKeyConstructionError<Self::EngineError>> {
        LweBootstrapKeyConstructionError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;

        Ok(unsafe {
            self.construct_lwe_bootstrap_key_unchecked(
                container,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: Vec<u32>,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKey32 {
        LweBootstrapKey32(ImplStandardBootstrapKey::from_container(
            container,
            glwe_size,
            poly_size,
            decomposition_level_count,
            decomposition_base_log,
        ))
    }
}

impl LweBootstrapKeyConstructionEngine<Vec<u64>, LweBootstrapKey64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u64; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let lwe_bootstrap_key: LweBootstrapKey64 = engine.construct_lwe_bootstrap_key(
    ///     owned_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     base_log,
    ///     level,
    /// )?;
    ///
    /// # assert_eq!(lwe_dimension, lwe_bootstrap_key.input_lwe_dimension());
    /// # assert_eq!(glwe_size, lwe_bootstrap_key.glwe_dimension().to_glwe_size());
    /// # assert_eq!(polynomial_size, lwe_bootstrap_key.polynomial_size());
    /// # assert_eq!(level, lwe_bootstrap_key.decomposition_level_count());
    /// # assert_eq!(base_log, lwe_bootstrap_key.decomposition_base_log());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: Vec<u64>,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweBootstrapKey64, LweBootstrapKeyConstructionError<Self::EngineError>> {
        LweBootstrapKeyConstructionError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;

        Ok(unsafe {
            self.construct_lwe_bootstrap_key_unchecked(
                container,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: Vec<u64>,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKey64 {
        LweBootstrapKey64(ImplStandardBootstrapKey::from_container(
            container,
            glwe_size,
            poly_size,
            decomposition_level_count,
            decomposition_base_log,
        ))
    }
}

impl<'data> LweBootstrapKeyConstructionEngine<&'data mut [u32], LweBootstrapKeyMutView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let mut owned_container =
    ///     vec![0_u32; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let mut slice = owned_container.as_mut_slice();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyMutView32 =
    ///     engine.construct_lwe_bootstrap_key(slice, glwe_size, polynomial_size, base_log, level)?;
    ///
    /// # assert_eq!(lwe_dimension, lwe_bootstrap_key.input_lwe_dimension());
    /// # assert_eq!(glwe_size, lwe_bootstrap_key.glwe_dimension().to_glwe_size());
    /// # assert_eq!(polynomial_size, lwe_bootstrap_key.polynomial_size());
    /// # assert_eq!(level, lwe_bootstrap_key.decomposition_level_count());
    /// # assert_eq!(base_log, lwe_bootstrap_key.decomposition_base_log());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: &'data mut [u32],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweBootstrapKeyMutView32<'data>, LweBootstrapKeyConstructionError<Self::EngineError>>
    {
        LweBootstrapKeyConstructionError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;

        Ok(unsafe {
            self.construct_lwe_bootstrap_key_unchecked(
                container,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: &'data mut [u32],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKeyMutView32<'data> {
        LweBootstrapKeyMutView32(ImplStandardBootstrapKey::from_container(
            container,
            glwe_size,
            poly_size,
            decomposition_level_count,
            decomposition_base_log,
        ))
    }
}

impl<'data> LweBootstrapKeyConstructionEngine<&'data mut [u64], LweBootstrapKeyMutView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let mut owned_container =
    ///     vec![0_u64; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let mut slice = owned_container.as_mut_slice();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyMutView64 =
    ///     engine.construct_lwe_bootstrap_key(slice, glwe_size, polynomial_size, base_log, level)?;
    ///
    /// # assert_eq!(lwe_dimension, lwe_bootstrap_key.input_lwe_dimension());
    /// # assert_eq!(glwe_size, lwe_bootstrap_key.glwe_dimension().to_glwe_size());
    /// # assert_eq!(polynomial_size, lwe_bootstrap_key.polynomial_size());
    /// # assert_eq!(level, lwe_bootstrap_key.decomposition_level_count());
    /// # assert_eq!(base_log, lwe_bootstrap_key.decomposition_base_log());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: &'data mut [u64],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweBootstrapKeyMutView64<'data>, LweBootstrapKeyConstructionError<Self::EngineError>>
    {
        LweBootstrapKeyConstructionError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;

        Ok(unsafe {
            self.construct_lwe_bootstrap_key_unchecked(
                container,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: &'data mut [u64],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKeyMutView64<'data> {
        LweBootstrapKeyMutView64(ImplStandardBootstrapKey::from_container(
            container,
            glwe_size,
            poly_size,
            decomposition_level_count,
            decomposition_base_log,
        ))
    }
}

impl<'data> LweBootstrapKeyConstructionEngine<&'data [u32], LweBootstrapKeyView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u32; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = owned_container.as_slice();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyView32 =
    ///     engine.construct_lwe_bootstrap_key(slice, glwe_size, polynomial_size, base_log, level)?;
    ///
    /// # assert_eq!(lwe_dimension, lwe_bootstrap_key.input_lwe_dimension());
    /// # assert_eq!(glwe_size, lwe_bootstrap_key.glwe_dimension().to_glwe_size());
    /// # assert_eq!(polynomial_size, lwe_bootstrap_key.polynomial_size());
    /// # assert_eq!(level, lwe_bootstrap_key.decomposition_level_count());
    /// # assert_eq!(base_log, lwe_bootstrap_key.decomposition_base_log());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: &'data [u32],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweBootstrapKeyView32<'data>, LweBootstrapKeyConstructionError<Self::EngineError>>
    {
        LweBootstrapKeyConstructionError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;

        Ok(unsafe {
            self.construct_lwe_bootstrap_key_unchecked(
                container,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: &'data [u32],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKeyView32<'data> {
        LweBootstrapKeyView32(ImplStandardBootstrapKey::from_container(
            container,
            glwe_size,
            poly_size,
            decomposition_level_count,
            decomposition_base_log,
        ))
    }
}

impl<'data> LweBootstrapKeyConstructionEngine<&'data [u64], LweBootstrapKeyView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u64; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = owned_container.as_slice();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyView64 =
    ///     engine.construct_lwe_bootstrap_key(slice, glwe_size, polynomial_size, base_log, level)?;
    ///
    /// # assert_eq!(lwe_dimension, lwe_bootstrap_key.input_lwe_dimension());
    /// # assert_eq!(glwe_size, lwe_bootstrap_key.glwe_dimension().to_glwe_size());
    /// # assert_eq!(polynomial_size, lwe_bootstrap_key.polynomial_size());
    /// # assert_eq!(level, lwe_bootstrap_key.decomposition_level_count());
    /// # assert_eq!(base_log, lwe_bootstrap_key.decomposition_base_log());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: &'data [u64],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<LweBootstrapKeyView64<'data>, LweBootstrapKeyConstructionError<Self::EngineError>>
    {
        LweBootstrapKeyConstructionError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;

        Ok(unsafe {
            self.construct_lwe_bootstrap_key_unchecked(
                container,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
            )
        })
    }

    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: &'data [u64],
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKeyView64<'data> {
        LweBootstrapKeyView64(ImplStandardBootstrapKey::from_container(
            container,
            glwe_size,
            poly_size,
            decomposition_level_count,
            decomposition_base_log,
        ))
    }
}
