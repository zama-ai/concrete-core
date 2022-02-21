use crate::backends::core::implementation::engines::CoreEngine;
use crate::specification::engines::{
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError,
};
use crate::specification::entities::LweBootstrapKeyEntity;

impl<Key> LweBootstrapKeyConversionEngine<Key, Key> for CoreEngine
    where
        Key: LweBootstrapKeyEntity + Clone,
{
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &Key,
    ) -> Result<Key, LweBootstrapKeyConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, input: &Key) -> Key {
        (*input).clone()
    }
}
