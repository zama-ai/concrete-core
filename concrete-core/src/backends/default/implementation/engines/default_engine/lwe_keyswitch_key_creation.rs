use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweSecretKey32, LweSecretKey64,
};
use crate::commons::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::specification::engines::{LweKeyswitchKeyCreationEngine, LweKeyswitchKeyCreationError};
use crate::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweKeyswitchKeyCreationEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweKeyswitchKeyCreationEngine<LweSecretKey32, LweSecretKey32, LweKeyswitchKey32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &LweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweKeyswitchKey32, LweKeyswitchKeyCreationError<Self::EngineError>> {
        LweKeyswitchKeyCreationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            32,
        )?;
        Ok(unsafe {
            self.create_lwe_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &LweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LweKeyswitchKey32 {
        let mut ksk = ImplLweKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.lwe_dimension(),
        );
        ksk.fill_with_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweKeyswitchKey32(ksk)
    }
}

/// # Description:
/// Implementation of [`LweKeyswitchKeyCreationEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweKeyswitchKeyCreationEngine<LweSecretKey64, LweSecretKey64, LweKeyswitchKey64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(keyswitch_key.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(keyswitch_key.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweKeyswitchKey64, LweKeyswitchKeyCreationError<Self::EngineError>> {
        LweKeyswitchKeyCreationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            64,
        )?;
        Ok(unsafe {
            self.create_lwe_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
            )
        })
    }

    unsafe fn create_lwe_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> LweKeyswitchKey64 {
        let mut ksk = ImplLweKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.lwe_dimension(),
        );
        ksk.fill_with_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweKeyswitchKey64(ksk)
    }
}
