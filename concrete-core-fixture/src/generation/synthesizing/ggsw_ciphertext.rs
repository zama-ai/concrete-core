use crate::generation::prototyping::PrototypesGgswCiphertext;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GgswCiphertextEntity;

/// A trait allowing to synthesize an actual ggsw ciphertext entity from a prototype.
pub trait SynthesizesGgswCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GgswCiphertext,
>: PrototypesGgswCiphertext<Precision, KeyDistribution> where
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
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GgswCiphertext32, GgswCiphertext64};

    impl SynthesizesGgswCiphertext<Precision32, BinaryKeyDistribution, GgswCiphertext32> for Maker {
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

    impl SynthesizesGgswCiphertext<Precision64, BinaryKeyDistribution, GgswCiphertext64> for Maker {
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

#[cfg(feature = "backend_fft")]
mod backend_fft {
    use crate::generation::synthesizing::SynthesizesGgswCiphertext;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        FftFourierGgswCiphertext32, FftFourierGgswCiphertext64, GgswCiphertextConversionEngine,
    };

    impl SynthesizesGgswCiphertext<Precision32, BinaryKeyDistribution, FftFourierGgswCiphertext32>
        for Maker
    {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> FftFourierGgswCiphertext32 {
            self.fft_engine
                .convert_ggsw_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            _entity: FftFourierGgswCiphertext32,
        ) -> Self::GgswCiphertextProto {
            // FIXME:
            unimplemented!("The backward fourier conversion was not yet implemented");
        }

        fn destroy_ggsw_ciphertext(&mut self, _entity: FftFourierGgswCiphertext32) {}
    }

    impl SynthesizesGgswCiphertext<Precision64, BinaryKeyDistribution, FftFourierGgswCiphertext64>
        for Maker
    {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> FftFourierGgswCiphertext64 {
            self.fft_engine
                .convert_ggsw_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            _entity: FftFourierGgswCiphertext64,
        ) -> Self::GgswCiphertextProto {
            // FIXME:
            unimplemented!("The backward fourier conversion was not yet implemented");
        }

        fn destroy_ggsw_ciphertext(&mut self, _entity: FftFourierGgswCiphertext64) {}
    }
}

#[cfg(feature = "backend_ntt")]
mod backend_ntt {
    use crate::generation::synthesizing::SynthesizesGgswCiphertext;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        GgswCiphertextConversionEngine, NttFourierGgswCiphertext32, NttFourierGgswCiphertext64,
    };

    impl SynthesizesGgswCiphertext<Precision32, BinaryKeyDistribution, NttFourierGgswCiphertext32>
        for Maker
    {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> NttFourierGgswCiphertext32 {
            self.ntt_engine
                .convert_ggsw_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            _entity: NttFourierGgswCiphertext32,
        ) -> Self::GgswCiphertextProto {
            // FIXME:
            unimplemented!("The backward fourier conversion was not yet implemented");
        }

        fn destroy_ggsw_ciphertext(&mut self, _entity: NttFourierGgswCiphertext32) {}
    }

    impl SynthesizesGgswCiphertext<Precision64, BinaryKeyDistribution, NttFourierGgswCiphertext64>
        for Maker
    {
        fn synthesize_ggsw_ciphertext(
            &mut self,
            prototype: &Self::GgswCiphertextProto,
        ) -> NttFourierGgswCiphertext64 {
            self.ntt_engine
                .convert_ggsw_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_ggsw_ciphertext(
            &mut self,
            _entity: NttFourierGgswCiphertext64,
        ) -> Self::GgswCiphertextProto {
            // FIXME:
            unimplemented!("The backward fourier conversion was not yet implemented");
        }

        fn destroy_ggsw_ciphertext(&mut self, _entity: NttFourierGgswCiphertext64) {}
    }
}
