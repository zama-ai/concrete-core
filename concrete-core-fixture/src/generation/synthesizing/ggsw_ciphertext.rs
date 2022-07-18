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

mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryGgswCiphertext32, ProtoBinaryGgswCiphertext64};
    use crate::generation::synthesizing::SynthesizesGgswCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{GgswCiphertext32, GgswCiphertext64};

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

        fn destroy_ggsw_ciphertext(&mut self, _entity: GgswCiphertext32) {}
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

        fn destroy_ggsw_ciphertext(&mut self, _entity: GgswCiphertext64) {}
    }
}

#[cfg(feature = "backend_fftw")]
mod backend_fftw {
    use crate::generation::synthesizing::SynthesizesGgswCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        FftwFourierGgswCiphertext32, FftwFourierGgswCiphertext64, GgswCiphertextConversionEngine,
    };

    impl SynthesizesGgswCiphertext<Precision32, FftwFourierGgswCiphertext32> for Maker {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> FftwFourierGgswCiphertext32 {
            self.fftw_engine
                .convert_ggsw_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            _entity: FftwFourierGgswCiphertext32,
        ) -> Self::GgswCiphertextProto {
            // FIXME:
            unimplemented!("The backward fourier conversion was not yet implemented");
        }

        fn destroy_ggsw_ciphertext(&mut self, _entity: FftwFourierGgswCiphertext32) {}
    }

    impl SynthesizesGgswCiphertext<Precision64, FftwFourierGgswCiphertext64> for Maker {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> FftwFourierGgswCiphertext64 {
            self.fftw_engine
                .convert_ggsw_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            _entity: FftwFourierGgswCiphertext64,
        ) -> Self::GgswCiphertextProto {
            // FIXME:
            unimplemented!("The backward fourier conversion was not yet implemented");
        }

        fn destroy_ggsw_ciphertext(&mut self, _entity: FftwFourierGgswCiphertext64) {}
    }
}
