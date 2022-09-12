use crate::prelude::{
    DefaultEngine, DefaultError, EncoderArrayCreationEngine, EncoderArrayCreationError,
    FloatEncoderArray, FloatEncoderCenterRadiusConfig, FloatEncoderMinMaxConfig,
};

/// # Description:
/// Implementation of [`EncoderArrayCreationEngine`] for [`DefaultEngine`] that creates an encoder
/// array to encode arrays of 64 bits floating point numbers.
impl EncoderArrayCreationEngine<FloatEncoderMinMaxConfig, FloatEncoderArray> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder_array = engine.create_encoder_array_from(
    ///     vec![
    ///         FloatEncoderMinMaxConfig {
    ///             min: 0.,
    ///             max: 10.,
    ///             nb_bit_precision: 8,
    ///             nb_bit_padding: 1,
    ///         };
    ///         1
    ///     ]
    ///     .as_slice(),
    /// )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_encoder_array_from(
        &mut self,
        config: &[FloatEncoderMinMaxConfig],
    ) -> Result<FloatEncoderArray, EncoderArrayCreationError<Self::EngineError>> {
        if config.iter().any(|c| c.min >= c.max) {
            return Err(EncoderArrayCreationError::Engine(
                DefaultError::FloatEncoderMinMaxOrder,
            ));
        } else if config.iter().any(|c| c.nb_bit_precision == 0) {
            return Err(EncoderArrayCreationError::Engine(
                DefaultError::FloatEncoderNullPrecision,
            ));
        }
        Ok(unsafe { self.create_encoder_array_from_unchecked(config) })
    }

    unsafe fn create_encoder_array_from_unchecked(
        &mut self,
        config: &[FloatEncoderMinMaxConfig],
    ) -> FloatEncoderArray {
        FloatEncoderArray(
            config
                .iter()
                .map(FloatEncoderMinMaxConfig::to_commons)
                .collect(),
        )
    }
}

/// # Description:
/// Implementation of [`EncoderArrayCreationEngine`] for [`DefaultEngine`] that creates an encoder
/// array to encode arrays of 64 bits floating point numbers.
impl EncoderArrayCreationEngine<FloatEncoderCenterRadiusConfig, FloatEncoderArray>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder_array = engine.create_encoder_array_from(&vec![
    ///     FloatEncoderCenterRadiusConfig {
    ///         center: 10.,
    ///         radius: 5.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     1
    /// ])?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_encoder_array_from(
        &mut self,
        config: &[FloatEncoderCenterRadiusConfig],
    ) -> Result<FloatEncoderArray, EncoderArrayCreationError<Self::EngineError>> {
        if config.iter().any(|c| c.radius <= 0.) {
            return Err(EncoderArrayCreationError::Engine(
                DefaultError::FloatEncoderNullRadius,
            ));
        } else if config.iter().any(|c| c.nb_bit_precision == 0) {
            return Err(EncoderArrayCreationError::Engine(
                DefaultError::FloatEncoderNullPrecision,
            ));
        }
        Ok(unsafe { self.create_encoder_array_from_unchecked(config) })
    }

    unsafe fn create_encoder_array_from_unchecked(
        &mut self,
        config: &[FloatEncoderCenterRadiusConfig],
    ) -> FloatEncoderArray {
        FloatEncoderArray(
            config
                .iter()
                .map(FloatEncoderCenterRadiusConfig::to_commons)
                .collect(),
        )
    }
}
