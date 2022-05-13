use concrete_commons::dispersion::StandardDev;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

use crate::backends::core::entities::{
    CleartextVector64, FunctionalPackingKeyswitchKey32, FunctionalPackingKeyswitchKey64,
};
use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweSecretKey32, LweSecretKey64};
use crate::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey as ImplFunctionalPackingKeyswitchKey;
use crate::backends::core::private::math::polynomial::Polynomial;
use crate::backends::core::private::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::CleartextVector32;
use crate::prelude::{
    FunctionalPackingKeyswitchKeyCreationError, GlweSecretKey32, GlweSecretKey64,
    GlweSecretKeyEntity,
};
use crate::specification::engines::FunctionalPackingKeyswitchKeyCreationEngine;
use crate::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`FunctionalPackingKeyswitchKeyCreationEngine`] for [`CoreEngine`] that
/// operates on 32 bits integers.
impl
    FunctionalPackingKeyswitchKeyCreationEngine<
        LweSecretKey32,
        GlweSecretKey32,
        FunctionalPackingKeyswitchKey32,
        CleartextVector32,
        u32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, GlweDimension
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(10);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomposition_base_log = DecompositionBaseLog(3);
    /// let decomposition_level_count = DecompositionLevelCount(5);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey32 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 = engine.create_glwe_secret_key(output_glwe_dimension,
    /// polynomial_size)?;    
    ///
    /// let val = vec![1_u32; output_key.polynomial_size().0];
    /// let polynomial: CleartextVector32 = engine.create_cleartext_vector(&val)?;
    /// let functional_packing_keyswitch_key = engine.create_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    ///     |x|x,
    ///     &polynomial,    
    /// )?;
    /// #
    /// assert_eq!(
    /// #     functional_packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     functional_packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(functional_packing_keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(functional_packing_keyswitch_key.output_glwe_dimension(), output_glwe_dimension);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(functional_packing_keyswitch_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_functional_packing_keyswitch_key<F: Fn(u32) -> u32>(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: F,
        polynomial: &CleartextVector32,
    ) -> Result<
        FunctionalPackingKeyswitchKey32,
        FunctionalPackingKeyswitchKeyCreationError<Self::EngineError>,
    > {
        FunctionalPackingKeyswitchKeyCreationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            32,
        )?;
        Ok(unsafe {
            self.create_functional_packing_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
                f,
                polynomial,
            )
        })
    }

    unsafe fn create_functional_packing_keyswitch_key_unchecked<F: Fn(u32) -> u32>(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: F,
        polynomial: &CleartextVector32,
    ) -> FunctionalPackingKeyswitchKey32 {
        let mut ksk = ImplFunctionalPackingKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.glwe_dimension(),
            output_key.polynomial_size(),
        );
        let poly = Polynomial::from_container(polynomial.0.as_tensor().as_slice().to_vec());

        ksk.fill_with_functional_packing_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
            f,
            &poly,
        );
        FunctionalPackingKeyswitchKey32(ksk)
    }
}

/// # Description:
/// Implementation of [`FunctionalPackingKeyswitchKeyCreationEngine`] for [`CoreEngine`] that
/// operates on 64 bits integers.
impl
    FunctionalPackingKeyswitchKeyCreationEngine<
        LweSecretKey64,
        GlweSecretKey64,
        FunctionalPackingKeyswitchKey64,
        CleartextVector64,
        u64,
    > for CoreEngine
{
    fn create_functional_packing_keyswitch_key<F: Fn(u64) -> u64>(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: F,
        polynomial: &CleartextVector64,
    ) -> Result<
        FunctionalPackingKeyswitchKey64,
        FunctionalPackingKeyswitchKeyCreationError<Self::EngineError>,
    > {
        FunctionalPackingKeyswitchKeyCreationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            64,
        )?;
        Ok(unsafe {
            self.create_functional_packing_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
                f,
                polynomial,
            )
        })
    }

    unsafe fn create_functional_packing_keyswitch_key_unchecked<F: Fn(u64) -> u64>(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: F,
        polynomial: &CleartextVector64,
    ) -> FunctionalPackingKeyswitchKey64 {
        let mut ksk = ImplFunctionalPackingKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.glwe_dimension(),
            output_key.polynomial_size(),
        );
        let poly = Polynomial::from_container(polynomial.0.as_tensor().as_slice().to_vec());

        ksk.fill_with_functional_packing_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
            f,
            &poly,
        );
        FunctionalPackingKeyswitchKey64(ksk)
    }
}
