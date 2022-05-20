use crate::generation::prototyping::PrototypesLweSeededCiphertext;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweSeededCiphertextEntity;

/// A trait allowing to synthesize an actual LweSeededCiphertextEntity from a prototype.
pub trait SynthesizesLweSeededCiphertext<Precision: IntegerPrecision, LweSeededCiphertext>:
    PrototypesLweSeededCiphertext<Precision, LweSeededCiphertext::KeyDistribution>
where
    LweSeededCiphertext: LweSeededCiphertextEntity,
{
    fn synthesize_lwe_seeded_ciphertext(
        &mut self,
        prototype: &Self::LweSeededCiphertextProto,
    ) -> LweSeededCiphertext;
    fn unsynthesize_lwe_seeded_ciphertext(
        &mut self,
        entity: LweSeededCiphertext,
    ) -> Self::LweSeededCiphertextProto;
    fn destroy_lwe_seeded_ciphertext(&mut self, entity: LweSeededCiphertext);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryLweSeededCiphertext32, ProtoBinaryLweSeededCiphertext64,
    };
    use crate::generation::synthesizing::SynthesizesLweSeededCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, LweSeededCiphertext32, LweSeededCiphertext64};

    impl SynthesizesLweSeededCiphertext<Precision32, LweSeededCiphertext32> for Maker {
        fn synthesize_lwe_seeded_ciphertext(
            &mut self,
            prototype: &Self::LweSeededCiphertextProto,
        ) -> LweSeededCiphertext32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_ciphertext(
            &mut self,
            entity: LweSeededCiphertext32,
        ) -> Self::LweSeededCiphertextProto {
            ProtoBinaryLweSeededCiphertext32(entity)
        }

        fn destroy_lwe_seeded_ciphertext(&mut self, entity: LweSeededCiphertext32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesLweSeededCiphertext<Precision64, LweSeededCiphertext64> for Maker {
        fn synthesize_lwe_seeded_ciphertext(
            &mut self,
            prototype: &Self::LweSeededCiphertextProto,
        ) -> LweSeededCiphertext64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_ciphertext(
            &mut self,
            entity: LweSeededCiphertext64,
        ) -> Self::LweSeededCiphertextProto {
            ProtoBinaryLweSeededCiphertext64(entity)
        }

        fn destroy_lwe_seeded_ciphertext(&mut self, entity: LweSeededCiphertext64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}
