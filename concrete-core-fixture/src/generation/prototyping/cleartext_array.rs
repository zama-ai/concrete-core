use crate::generation::prototypes::{
    CleartextArrayPrototype, ProtoCleartextArray32, ProtoCleartextArray64,
};
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_core::prelude::{CleartextArrayCreationEngine, CleartextArrayRetrievalEngine};

/// A trait allowing to manipulate cleartext array prototypes.
pub trait PrototypesCleartextArray<Precision: IntegerPrecision> {
    type CleartextArrayProto: CleartextArrayPrototype<Precision = Precision>;
    fn transform_raw_vec_to_cleartext_array(
        &mut self,
        raw: &[Precision::Raw],
    ) -> Self::CleartextArrayProto;
    fn transform_cleartext_array_to_raw_vec(
        &mut self,
        cleartext: &Self::CleartextArrayProto,
    ) -> Vec<Precision::Raw>;
}

impl PrototypesCleartextArray<Precision32> for Maker {
    type CleartextArrayProto = ProtoCleartextArray32;

    fn transform_raw_vec_to_cleartext_array(&mut self, raw: &[u32]) -> Self::CleartextArrayProto {
        ProtoCleartextArray32(
            self.default_engine
                .create_cleartext_array_from(raw)
                .unwrap(),
        )
    }

    fn transform_cleartext_array_to_raw_vec(
        &mut self,
        cleartext: &Self::CleartextArrayProto,
    ) -> Vec<u32> {
        self.default_engine
            .retrieve_cleartext_array(&cleartext.0)
            .unwrap()
    }
}

impl PrototypesCleartextArray<Precision64> for Maker {
    type CleartextArrayProto = ProtoCleartextArray64;

    fn transform_raw_vec_to_cleartext_array(&mut self, raw: &[u64]) -> Self::CleartextArrayProto {
        ProtoCleartextArray64(
            self.default_engine
                .create_cleartext_array_from(raw)
                .unwrap(),
        )
    }

    fn transform_cleartext_array_to_raw_vec(
        &mut self,
        cleartext: &Self::CleartextArrayProto,
    ) -> Vec<u64> {
        self.default_engine
            .retrieve_cleartext_array(&cleartext.0)
            .unwrap()
    }
}
