use crate::generation::prototyping::PrototypesCleartextArray;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::CleartextArrayEntity;

/// A trait allowing to synthesize an actual cleartext array entity from a prototype.
pub trait SynthesizesCleartextArray<Precision: IntegerPrecision, CleartextArray>:
    PrototypesCleartextArray<Precision>
where
    CleartextArray: CleartextArrayEntity,
{
    fn synthesize_cleartext_array(
        &mut self,
        prototype: &Self::CleartextArrayProto,
    ) -> CleartextArray;
    fn unsynthesize_cleartext_array(&mut self, entity: CleartextArray)
        -> Self::CleartextArrayProto;
    fn destroy_cleartext_array(&mut self, entity: CleartextArray);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoCleartextArray32, ProtoCleartextArray64};
    use crate::generation::synthesizing::SynthesizesCleartextArray;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{CleartextArray32, CleartextArray64};

    impl SynthesizesCleartextArray<Precision32, CleartextArray32> for Maker {
        fn synthesize_cleartext_array(
            &mut self,
            prototype: &Self::CleartextArrayProto,
        ) -> CleartextArray32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_cleartext_array(
            &mut self,
            entity: CleartextArray32,
        ) -> Self::CleartextArrayProto {
            ProtoCleartextArray32(entity)
        }

        fn destroy_cleartext_array(&mut self, _entity: CleartextArray32) {}
    }

    impl SynthesizesCleartextArray<Precision64, CleartextArray64> for Maker {
        fn synthesize_cleartext_array(
            &mut self,
            prototype: &Self::CleartextArrayProto,
        ) -> CleartextArray64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_cleartext_array(
            &mut self,
            entity: CleartextArray64,
        ) -> Self::CleartextArrayProto {
            ProtoCleartextArray64(entity)
        }

        fn destroy_cleartext_array(&mut self, _entity: CleartextArray64) {}
    }
}
