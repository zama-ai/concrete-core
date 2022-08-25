use crate::generation::prototypes::{
    LweSeededBootstrapKeyPrototype, ProtoBinaryBinaryLweBootstrapKey32,
    ProtoBinaryBinaryLweBootstrapKey64, ProtoBinaryBinaryLweSeededBootstrapKey32,
    ProtoBinaryBinaryLweSeededBootstrapKey64,
};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::lwe_bootstrap_key::PrototypesLweBootstrapKey;
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use concrete_core::prelude::{
    LweSeededBootstrapKeyGenerationEngine,
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine,
};

/// A trait allowing to manipulate LWE seeded bootstrap key prototypes.
pub trait PrototypesLweSeededBootstrapKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
    + PrototypesLweBootstrapKey<Precision, InputKeyDistribution, OutputKeyDistribution>
{
    type LweSeededBootstrapKeyProto: LweSeededBootstrapKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_lwe_seeded_bootstrap_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweSeededBootstrapKeyProto;

    fn tranform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(
        &mut self,
        seeded_bsk: &Self::LweSeededBootstrapKeyProto,
    ) -> Self::LweBootstrapKeyProto;
}

impl PrototypesLweSeededBootstrapKey<Precision32, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweSeededBootstrapKeyProto = ProtoBinaryBinaryLweSeededBootstrapKey32;

    fn new_lwe_seeded_bootstrap_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweSeededBootstrapKeyProto {
        ProtoBinaryBinaryLweSeededBootstrapKey32(
            self.default_parallel_engine
                .generate_new_lwe_seeded_bootstrap_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }

    fn tranform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(
        &mut self,
        seeded_bsk: &Self::LweSeededBootstrapKeyProto,
    ) -> Self::LweBootstrapKeyProto {
        ProtoBinaryBinaryLweBootstrapKey32(
            self.default_engine
                .transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(seeded_bsk.0.to_owned())
                .unwrap(),
        )
    }
}

impl PrototypesLweSeededBootstrapKey<Precision64, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweSeededBootstrapKeyProto = ProtoBinaryBinaryLweSeededBootstrapKey64;

    fn new_lwe_seeded_bootstrap_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweSeededBootstrapKeyProto {
        ProtoBinaryBinaryLweSeededBootstrapKey64(
            self.default_parallel_engine
                .generate_new_lwe_seeded_bootstrap_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }

    fn tranform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(
        &mut self,
        seeded_bsk: &Self::LweSeededBootstrapKeyProto,
    ) -> Self::LweBootstrapKeyProto {
        ProtoBinaryBinaryLweBootstrapKey64(
            self.default_engine
                .transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(seeded_bsk.0.to_owned())
                .unwrap(),
        )
    }
}
