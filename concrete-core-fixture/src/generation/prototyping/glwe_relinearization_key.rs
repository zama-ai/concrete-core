use crate::generation::prototypes::{GlweRelinearizationKeyPrototype, ProtoGlweRelinearizationKey32, ProtoGlweRelinearizationKey64,};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::GlweRelinearizationKeyCreationEngine;

/// A trait allowing to manipulate GLWE relinearization key prototypes.
pub trait PrototypesGlweRelinearizationKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
PrototypesGlweRelinearizationKey<Precision, KeyDistribution>
+ PrototypesGlweSecretKey<Precision, KeyDistribution>
{
    type GlweRelinearizationKeyProto: GlweRelinearizationKeyPrototype<
        Precision = Precision,
        InputKeyDistribution =KeyDistribution,
    >;
    fn new_glwe_relinearization_key(
        &mut self,
        input_key: &<Self as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level: DecompositionLevelCount,
        noise: Variance,
    ) -> Self::GlweRelinearizationKeyProto;
}

impl PrototypesGlweRelinearizationKey<Precision32, BinaryKeyDistribution>
for Maker
{
    type GlweRelinearizationKeyProto = ProtoGlweRelinearizationKey32;

    fn new_glwe_relinearization_key(
        &mut self,
        input_key: &Self::GlweSecretKeyProto,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level: DecompositionLevelCount,
        noise: Variance,
    ) -> Self::GlweRelinearizationKeyProto {
        ProtoGlweRelinearizationKey32(
            self.fftw_engine
                .create_glwe_relinearization_key(
                    &input_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }
}

impl PrototypesGlweRelinearizationKey<Precision64, BinaryKeyDistribution>
for Maker
{
    type GlweRelinearizationKeyProto = ProtoStandardRelinearizationKey32;

    fn new_glwe_relinearization_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level: DecompositionLevelCount,
        noise: Variance,
    ) -> Self::GlweRelinearizationKeyProto {
        ProtoGlweRelinearizationKey64(
            self.fftw_engine
                .new_glwe_relinearization_key(
                    &input_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }
}
