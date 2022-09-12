use crate::commons::crypto::encoding::{Encoder, PlaintextList};
use crate::prelude::{
    CleartextArrayEncodingEngine, CleartextArrayEncodingError, CleartextArrayF64, DefaultEngine,
    DefaultError, FloatEncoderArray, PlaintextArray32, PlaintextArray64,
};

/// # Description:
/// Implementation of [`CleartextArrayEncodingEngine`] for [`DefaultEngine`] that encodes 64 bits
/// floating point numbers to 32 bits integers.
impl CleartextArrayEncodingEngine<FloatEncoderArray, CleartextArrayF64, PlaintextArray32>
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
    ///     FloatEncoderMinMaxConfig {
    ///         min: 0.,
    ///         max: 10.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     100
    /// ])?;
    /// let cleartext_array: CleartextArrayF64 = engine.create_cleartext_array_from(&vec![5.; 100])?;
    /// let plaintext_array: PlaintextArray32 =
    ///     engine.encode_cleartext_array(&encoder_array, &cleartext_array)?;
    /// assert_eq!(
    ///     cleartext_array.cleartext_count().0,
    ///     plaintext_array.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encode_cleartext_array(
        &mut self,
        encoder_array: &FloatEncoderArray,
        cleartext_array: &CleartextArrayF64,
    ) -> Result<PlaintextArray32, CleartextArrayEncodingError<Self::EngineError>> {
        CleartextArrayEncodingError::perform_generic_checks(encoder_array, cleartext_array)?;
        let interval_check_failed = encoder_array
            .0
            .iter()
            .zip(cleartext_array.0.cleartext_iter())
            .any(|(encoder, cleartext)| encoder.is_message_out_of_range(cleartext.0));
        if interval_check_failed {
            return Err(CleartextArrayEncodingError::Engine(
                DefaultError::FloatEncoderMessageOutsideInterval,
            ));
        }
        Ok(unsafe { self.encode_cleartext_array_unchecked(encoder_array, cleartext_array) })
    }

    unsafe fn encode_cleartext_array_unchecked(
        &mut self,
        encoder_array: &FloatEncoderArray,
        cleartext_array: &CleartextArrayF64,
    ) -> PlaintextArray32 {
        PlaintextArray32(PlaintextList::from_container(
            encoder_array
                .0
                .iter()
                .zip(cleartext_array.0.cleartext_iter())
                .map(|(enc, clear)| enc.encode(*clear).0)
                .collect::<Vec<_>>(),
        ))
    }
}

/// # Description:
/// Implementation of [`CleartextArrayEncodingEngine`] for [`DefaultEngine`] that encodes 64 bits
/// floating point numbers to 64 bits integers.
impl CleartextArrayEncodingEngine<FloatEncoderArray, CleartextArrayF64, PlaintextArray64>
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
    ///     FloatEncoderMinMaxConfig {
    ///         min: 0.,
    ///         max: 10.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     100
    /// ])?;
    /// let cleartext_array: CleartextArrayF64 = engine.create_cleartext_array_from(&vec![5.; 100])?;
    /// let plaintext_array: PlaintextArray64 =
    ///     engine.encode_cleartext_array(&encoder_array, &cleartext_array)?;
    /// assert_eq!(
    ///     cleartext_array.cleartext_count().0,
    ///     plaintext_array.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encode_cleartext_array(
        &mut self,
        encoder_array: &FloatEncoderArray,
        cleartext_array: &CleartextArrayF64,
    ) -> Result<PlaintextArray64, CleartextArrayEncodingError<Self::EngineError>> {
        CleartextArrayEncodingError::perform_generic_checks(encoder_array, cleartext_array)?;
        let interval_check_failed = encoder_array
            .0
            .iter()
            .zip(cleartext_array.0.cleartext_iter())
            .any(|(encoder, cleartext)| encoder.is_message_out_of_range(cleartext.0));
        if interval_check_failed {
            return Err(CleartextArrayEncodingError::Engine(
                DefaultError::FloatEncoderMessageOutsideInterval,
            ));
        }
        Ok(unsafe { self.encode_cleartext_array_unchecked(encoder_array, cleartext_array) })
    }

    unsafe fn encode_cleartext_array_unchecked(
        &mut self,
        encoder_array: &FloatEncoderArray,
        cleartext_array: &CleartextArrayF64,
    ) -> PlaintextArray64 {
        PlaintextArray64(PlaintextList::from_container(
            encoder_array
                .0
                .iter()
                .zip(cleartext_array.0.cleartext_iter())
                .map(|(enc, clear)| enc.encode(*clear).0)
                .collect::<Vec<_>>(),
        ))
    }
}
