use crate::commons::crypto::encoding::{CleartextList, Encoder};
use crate::prelude::{
    CleartextArrayF64, DefaultEngine, FloatEncoderArray, PlaintextArray32, PlaintextArray64,
    PlaintextArrayDecodingEngine, PlaintextArrayDecodingError,
};

/// # Description:
/// Implementation of [`PlaintextArrayDecodingEngine`] for [`DefaultEngine`] that decodes 32 bits
/// integers to 64 bits floating point numbers.
impl PlaintextArrayDecodingEngine<FloatEncoderArray, PlaintextArray32, CleartextArrayF64>
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
    /// let recovered_cleartext_array: CleartextArrayF64 =
    ///     engine.decode_plaintext_array(&encoder_array, &plaintext_array)?;
    /// assert_eq!(
    ///     recovered_cleartext_array.cleartext_count().0,
    ///     plaintext_array.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decode_plaintext_array(
        &mut self,
        encoder: &FloatEncoderArray,
        input: &PlaintextArray32,
    ) -> Result<CleartextArrayF64, PlaintextArrayDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_array_unchecked(encoder, input) })
    }

    unsafe fn decode_plaintext_array_unchecked(
        &mut self,
        encoder: &FloatEncoderArray,
        input: &PlaintextArray32,
    ) -> CleartextArrayF64 {
        CleartextArrayF64(CleartextList::from_container(
            encoder
                .0
                .iter()
                .zip(input.0.plaintext_iter())
                .map(|(enc, p)| enc.decode(*p).0)
                .collect::<Vec<_>>(),
        ))
    }
}

/// # Description:
/// Implementation of [`PlaintextArrayDecodingEngine`] for [`DefaultEngine`] that decodes 64 bits
/// integers to 64 bits floating point numbers.
impl PlaintextArrayDecodingEngine<FloatEncoderArray, PlaintextArray64, CleartextArrayF64>
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
    /// let recovered_cleartext_array: CleartextArrayF64 =
    ///     engine.decode_plaintext_array(&encoder_array, &plaintext_array)?;
    /// assert_eq!(
    ///     recovered_cleartext_array.cleartext_count().0,
    ///     plaintext_array.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decode_plaintext_array(
        &mut self,
        encoder: &FloatEncoderArray,
        input: &PlaintextArray64,
    ) -> Result<CleartextArrayF64, PlaintextArrayDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_array_unchecked(encoder, input) })
    }

    unsafe fn decode_plaintext_array_unchecked(
        &mut self,
        encoder: &FloatEncoderArray,
        input: &PlaintextArray64,
    ) -> CleartextArrayF64 {
        CleartextArrayF64(CleartextList::from_container(
            encoder
                .0
                .iter()
                .zip(input.0.plaintext_iter())
                .map(|(enc, p)| enc.decode(*p).0)
                .collect::<Vec<_>>(),
        ))
    }
}
