use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesGlweSecretKey, PrototypesLweSecretKey};
use crate::generation::synthesizing::{
    SynthesizesGlweSecretKey, SynthesizesLweBootstrapKey, SynthesizesLweSecretKey,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    GlweSecretKeyEntity, LweBootstrapKeyEntity, LweBootstrapKeyGenerationEngine, LweSecretKeyEntity,
};

/// A fixture for the types implementing the `LweBootstrapKeyGenerationEngine` trait.
pub struct LweBootstrapKeyGenerationFixture;

#[derive(Debug)]
pub struct LweBootstrapKeyGenerationParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
    pub noise: Variance,
}

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        LweSecretKey,
        GlweSecretKey,
        BootstrapKey,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (LweSecretKey, GlweSecretKey, BootstrapKey),
    > for LweBootstrapKeyGenerationFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweBootstrapKeyGenerationEngine<LweSecretKey, GlweSecretKey, BootstrapKey>,
    LweSecretKey: LweSecretKeyEntity,
    GlweSecretKey: GlweSecretKeyEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    Maker: SynthesizesLweSecretKey<Precision, InputKeyDistribution, LweSecretKey>
        + SynthesizesGlweSecretKey<Precision, OutputKeyDistribution, GlweSecretKey>
        + SynthesizesLweBootstrapKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            BootstrapKey,
        >,
{
    type Parameters = LweBootstrapKeyGenerationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, OutputKeyDistribution>>::GlweSecretKeyProto,
    );
    type PreExecutionContext = (LweSecretKey, GlweSecretKey);
    type PostExecutionContext = (BootstrapKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweBootstrapKeyGenerationParameters {
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(1024),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
                    noise: Variance(0.00000001),
                },
                LweBootstrapKeyGenerationParameters {
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(512),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
                    noise: Variance(0.00000001),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let proto_secret_key_lwe = <Maker as PrototypesLweSecretKey<
            Precision,
            InputKeyDistribution,
        >>::new_lwe_secret_key(maker, parameters.lwe_dimension);
        let proto_secret_key_glwe =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        (proto_secret_key_lwe, proto_secret_key_glwe)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key_lwe, proto_secret_key_glwe) = sample_proto;
        let synth_secret_key_lwe = maker.synthesize_lwe_secret_key(proto_secret_key_lwe);
        let synth_secret_key_glwe = maker.synthesize_glwe_secret_key(proto_secret_key_glwe);
        (synth_secret_key_lwe, synth_secret_key_glwe)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (sk_in, sk_out) = context;
        let sk = unsafe {
            engine.generate_new_lwe_bootstrap_key_unchecked(
                &sk_in,
                &sk_out,
                parameters.base_log,
                parameters.level,
                parameters.noise,
            )
        };
        (sk,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (bsk,) = context;
        maker.destroy_lwe_bootstrap_key(bsk);
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(_criteria: &Self::Criteria, _outputs: &[Self::Outcome]) -> bool {
        // The test to verify the generated key is not yet implemented.
        false
    }
}
