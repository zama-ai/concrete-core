use crate::backends::optalysys::implementation::engines::OptalysysEngine;
use crate::backends::optalysys::implementation::entities::{
    OptalysysFourierLweBootstrapKey32, OptalysysFourierLweBootstrapKey64,
};
use crate::specification::engines::{DestructionEngine, DestructionError};

impl DestructionEngine<OptalysysFourierLweBootstrapKey32> for OptalysysEngine {
    fn destroy(
        &mut self,
        mut entity: OptalysysFourierLweBootstrapKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut OptalysysFourierLweBootstrapKey32) {}
}

impl DestructionEngine<OptalysysFourierLweBootstrapKey64> for OptalysysEngine {
    fn destroy(
        &mut self,
        mut entity: OptalysysFourierLweBootstrapKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut OptalysysFourierLweBootstrapKey64) {}
}
