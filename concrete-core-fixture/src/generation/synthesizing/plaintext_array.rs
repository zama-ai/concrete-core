use crate::generation::prototyping::PrototypesPlaintextArray;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::PlaintextArrayEntity;

/// A trait allowing to synthesize an actual plaintext array entity from a prototype.
pub trait SynthesizesPlaintextArray<Precision: IntegerPrecision, PlaintextArray>:
    PrototypesPlaintextArray<Precision>
where
    PlaintextArray: PlaintextArrayEntity,
{
    fn synthesize_plaintext_array(
        &mut self,
        prototype: &Self::PlaintextArrayProto,
    ) -> PlaintextArray;
    fn unsynthesize_plaintext_array(&mut self, entity: PlaintextArray)
        -> Self::PlaintextArrayProto;
    fn destroy_plaintext_array(&mut self, entity: PlaintextArray);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoPlaintextArray32, ProtoPlaintextArray64};
    use crate::generation::synthesizing::SynthesizesPlaintextArray;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{PlaintextArray32, PlaintextArray64};

    impl SynthesizesPlaintextArray<Precision32, PlaintextArray32> for Maker {
        fn synthesize_plaintext_array(
            &mut self,
            prototype: &Self::PlaintextArrayProto,
        ) -> PlaintextArray32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_plaintext_array(
            &mut self,
            entity: PlaintextArray32,
        ) -> Self::PlaintextArrayProto {
            ProtoPlaintextArray32(entity)
        }

        fn destroy_plaintext_array(&mut self, _entity: PlaintextArray32) {}
    }

    impl SynthesizesPlaintextArray<Precision64, PlaintextArray64> for Maker {
        fn synthesize_plaintext_array(
            &mut self,
            prototype: &Self::PlaintextArrayProto,
        ) -> PlaintextArray64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_plaintext_array(
            &mut self,
            entity: PlaintextArray64,
        ) -> Self::PlaintextArrayProto {
            ProtoPlaintextArray64(entity)
        }

        fn destroy_plaintext_array(&mut self, _entity: PlaintextArray64) {}
    }
}
