use crate::generation::prototypes::{
    PlaintextArrayPrototype, ProtoPlaintextArray32, ProtoPlaintextArray64,
};
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_core::prelude::{PlaintextArrayCreationEngine, PlaintextArrayRetrievalEngine};

/// A trait allowing to manipulate plaintext array prototypes.
pub trait PrototypesPlaintextArray<Precision: IntegerPrecision> {
    type PlaintextArrayProto: PlaintextArrayPrototype<Precision = Precision>;
    fn transform_raw_vec_to_plaintext_array(
        &mut self,
        raw: &[Precision::Raw],
    ) -> Self::PlaintextArrayProto;
    fn transform_plaintext_array_to_raw_vec(
        &mut self,
        plaintext: &Self::PlaintextArrayProto,
    ) -> Vec<Precision::Raw>;
}

impl PrototypesPlaintextArray<Precision32> for Maker {
    type PlaintextArrayProto = ProtoPlaintextArray32;

    fn transform_raw_vec_to_plaintext_array(&mut self, raw: &[u32]) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray32(
            self.default_engine
                .create_plaintext_array_from(raw)
                .unwrap(),
        )
    }

    fn transform_plaintext_array_to_raw_vec(
        &mut self,
        plaintext: &Self::PlaintextArrayProto,
    ) -> Vec<u32> {
        self.default_engine
            .retrieve_plaintext_array(&plaintext.0)
            .unwrap()
    }
}

impl PrototypesPlaintextArray<Precision64> for Maker {
    type PlaintextArrayProto = ProtoPlaintextArray64;

    fn transform_raw_vec_to_plaintext_array(&mut self, raw: &[u64]) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray64(
            self.default_engine
                .create_plaintext_array_from(raw)
                .unwrap(),
        )
    }

    fn transform_plaintext_array_to_raw_vec(
        &mut self,
        plaintext: &Self::PlaintextArrayProto,
    ) -> Vec<u64> {
        self.default_engine
            .retrieve_plaintext_array(&plaintext.0)
            .unwrap()
    }
}
