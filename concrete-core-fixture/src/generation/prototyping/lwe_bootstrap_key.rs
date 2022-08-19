use crate::generation::prototypes::{
    LweBootstrapKeyPrototype, ProtoBinaryBinaryLweBootstrapKey32,
    ProtoBinaryBinaryLweBootstrapKey64,
};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use concrete_core::prelude::{
    LweBootstrapKeyConstructionEngine, LweBootstrapKeyConsumingRetrievalEngine,
    LweBootstrapKeyCreationEngine,
};

/// A trait allowing to manipulate LWE bootstrap key prototypes.
pub trait PrototypesLweBootstrapKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
{
    type LweBootstrapKeyProto: LweBootstrapKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_lwe_bootstrap_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweBootstrapKeyProto;
    fn transform_raw_vec_to_lwe_bootstrap_key(
        &mut self,
        raw: &[Precision::Raw],
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::LweBootstrapKeyProto;
    fn transform_lwe_bootstrap_key_to_raw_vec(
        &mut self,
        lwe_bootstrap_key: &Self::LweBootstrapKeyProto,
    ) -> Vec<Precision::Raw>;
}

impl PrototypesLweBootstrapKey<Precision32, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweBootstrapKeyProto = ProtoBinaryBinaryLweBootstrapKey32;

    fn new_lwe_bootstrap_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweBootstrapKeyProto {
        ProtoBinaryBinaryLweBootstrapKey32(
            self.default_parallel_engine
                .create_lwe_bootstrap_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }

    fn transform_raw_vec_to_lwe_bootstrap_key(
        &mut self,
        raw: &[u32],
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::LweBootstrapKeyProto {
        ProtoBinaryBinaryLweBootstrapKey32(
            self.default_engine
                .construct_lwe_bootstrap_key(
                    raw.to_owned(),
                    glwe_size,
                    polynomial_size,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap(),
        )
    }

    fn transform_lwe_bootstrap_key_to_raw_vec(
        &mut self,
        lwe_bootstrap_key: &Self::LweBootstrapKeyProto,
    ) -> Vec<u32> {
        let lwe_bootstrap_key = lwe_bootstrap_key.0.to_owned();
        self.default_engine
            .consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)
            .unwrap()
    }
}

impl PrototypesLweBootstrapKey<Precision64, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweBootstrapKeyProto = ProtoBinaryBinaryLweBootstrapKey64;

    fn new_lwe_bootstrap_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweBootstrapKeyProto {
        ProtoBinaryBinaryLweBootstrapKey64(
            self.default_parallel_engine
                .create_lwe_bootstrap_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_base_log,
                    decomposition_level,
                    noise,
                )
                .unwrap(),
        )
    }

    fn transform_raw_vec_to_lwe_bootstrap_key(
        &mut self,
        raw: &[u64],
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::LweBootstrapKeyProto {
        ProtoBinaryBinaryLweBootstrapKey64(
            self.default_engine
                .construct_lwe_bootstrap_key(
                    raw.to_owned(),
                    glwe_size,
                    polynomial_size,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap(),
        )
    }

    fn transform_lwe_bootstrap_key_to_raw_vec(
        &mut self,
        lwe_bootstrap_key: &Self::LweBootstrapKeyProto,
    ) -> Vec<u64> {
        let lwe_bootstrap_key = lwe_bootstrap_key.0.to_owned();
        self.default_engine
            .consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)
            .unwrap()
    }
}
