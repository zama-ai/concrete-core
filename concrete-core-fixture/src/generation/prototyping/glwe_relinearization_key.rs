use crate::generation::prototypes::{
    GlweRelinearizationKeyPrototype, ProtoStandardRelinearizationKey32, ProtoStandardRelinearizationKey64};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::GlweRelinearizationKeyCreationEngine;

/// A trait allowing to manipulate GLWE relinearization key prototypes.
pub trait PrototypesStandardRelinearizationKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
PrototypesStandardRelinearizationKey<Precision, InputKeyDistribution, OutputKeyDistribution>
+ PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
{
    type StandardRelinearizationKeyProto: GlweRelinearizationKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_glwe_relinearization_key(
        &mut self,
        input_key: &<Self as PrototypesGlweSecretKey<Precision, InputKeyDistribution>>::GlweSecretKeyProto,
        output_key: &Self::StandardRelinearizationKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::StandardRelinearizationKeyProto;
}

impl PrototypesStandardRelinearizationKey<Precision32, BinaryKeyDistribution, BinaryKeyDistribution>
for Maker
{
    type StandardRelinearizationKeyProto = ProtoStandardRelinearizationKey32;

    fn new_glwe_relinearization_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweBootstrapKeyProto {
        ProtoStandardRelinearizationKey32(
            // TODO: which engine?
            self.default_engine
                .new_glwe_relinearization_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }
}

impl PrototypesStandardRelinearizationKey<Precision64, BinaryKeyDistribution, BinaryKeyDistribution>
for Maker
{
    type StandardRelinearizationKeyProto = ProtoStandardRelinearizationKey32;

    fn new_glwe_relinearization_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweBootstrapKeyProto {
        ProtoStandardRelinearizationKey64(
            // TODO: which engine?
            self.default_engine
                .new_glwe_relinearization_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }
}
