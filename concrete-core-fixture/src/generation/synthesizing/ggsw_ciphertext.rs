use crate::generation::prototyping::PrototypesGgswCiphertext;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::GgswCiphertextEntity;

/// A trait allowing to synthesize an actual ggsw ciphertext entity from a prototype.
pub trait SynthesizesGgswCiphertext<Precision: IntegerPrecision, GgswCiphertext>:
    PrototypesGgswCiphertext<Precision, GgswCiphertext::KeyDistribution>
where
    GgswCiphertext: GgswCiphertextEntity,
{
    fn synthesize_ggsw_ciphertext(
        &mut self,
        prototype: &Self::GgswCiphertextProto,
    ) -> GgswCiphertext;
    fn unsynthesize_ggsw_ciphertext(&mut self, entity: GgswCiphertext)
        -> Self::GgswCiphertextProto;
    fn destroy_ggsw_ciphertext(&mut self, entity: GgswCiphertext);
}

#[cfg(feature = "backend_default")]
mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryGgswCiphertext32, ProtoBinaryGgswCiphertext64};
    use crate::generation::synthesizing::SynthesizesGgswCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, GgswCiphertext32, GgswCiphertext64};

    impl SynthesizesGgswCiphertext<Precision32, GgswCiphertext32> for Maker {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> GgswCiphertext32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            entity: GgswCiphertext32,
        ) -> Self::GgswCiphertextProto {
            ProtoBinaryGgswCiphertext32(entity)
        }

        fn destroy_ggsw_ciphertext(&mut self, entity: GgswCiphertext32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGgswCiphertext<Precision64, GgswCiphertext64> for Maker {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> GgswCiphertext64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            entity: GgswCiphertext64,
        ) -> Self::GgswCiphertextProto {
            ProtoBinaryGgswCiphertext64(entity)
        }

        fn destroy_ggsw_ciphertext(&mut self, entity: GgswCiphertext64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}
