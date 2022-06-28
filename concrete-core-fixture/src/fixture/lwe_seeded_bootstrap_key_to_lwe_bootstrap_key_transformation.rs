use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweSecretKey, PrototypesLweSecretKey, PrototypesLweSeededBootstrapKey,
};
use crate::generation::synthesizing::{
    SynthesizesGlweSecretKey, SynthesizesLweBootstrapKey, SynthesizesLweSecretKey,
    SynthesizesLweSeededBootstrapKey,
};
use crate::generation::{IntegerPrecision, Maker};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    GlweSecretKeyEntity, LweBootstrapKeyEntity, LweSecretKeyEntity, LweSeededBootstrapKeyEntity,
    LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine,
};

/// A fixture for the types implementing the
/// `LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine` trait.
pub struct LweSeededBootstrapKeyToLweBootstrapKeyTransformationFixture;

#[derive(Debug)]
pub struct LweSeededToLweBootstrapKeyTransformationParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
    pub noise: Variance,
}

impl<
        Precision,
        Engine,
        LweSecretKey,
        GlweSecretKey,
        InputSeededBootstrapKey,
        OutputBootstrapKey,
    >
    Fixture<
        Precision,
        Engine,
        (
            LweSecretKey,
            GlweSecretKey,
            InputSeededBootstrapKey,
            OutputBootstrapKey,
        ),
    > for LweSeededBootstrapKeyToLweBootstrapKeyTransformationFixture
where
    Precision: IntegerPrecision,
    Engine: LweSeededBootstrapKeyToLweBootstrapKeyTransformationEngine<
        InputSeededBootstrapKey,
        OutputBootstrapKey,
    >,
    LweSecretKey: LweSecretKeyEntity,
    GlweSecretKey: GlweSecretKeyEntity,
    InputSeededBootstrapKey: LweSeededBootstrapKeyEntity<
        InputKeyDistribution = LweSecretKey::KeyDistribution,
        OutputKeyDistribution = GlweSecretKey::KeyDistribution,
    >,
    OutputBootstrapKey: LweBootstrapKeyEntity<
        InputKeyDistribution = InputSeededBootstrapKey::InputKeyDistribution,
        OutputKeyDistribution = InputSeededBootstrapKey::OutputKeyDistribution,
    >,
    Maker: SynthesizesLweSecretKey<Precision, LweSecretKey>
        + SynthesizesGlweSecretKey<Precision, GlweSecretKey>
        + SynthesizesLweSeededBootstrapKey<Precision, InputSeededBootstrapKey>
        + SynthesizesLweBootstrapKey<Precision, OutputBootstrapKey>,
{
    type Parameters = LweSeededToLweBootstrapKeyTransformationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesLweSeededBootstrapKey<
            Precision,
            InputSeededBootstrapKey::InputKeyDistribution,
            InputSeededBootstrapKey::OutputKeyDistribution,
        >>::LweSeededBootstrapKeyProto,
    );
    type PreExecutionContext = (InputSeededBootstrapKey,);
    type PostExecutionContext = (OutputBootstrapKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededToLweBootstrapKeyTransformationParameters {
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(1024),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
                    noise: Variance(0.00000001),
                },
                LweSeededToLweBootstrapKeyTransformationParameters {
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
            LweSecretKey::KeyDistribution,
        >>::new_lwe_secret_key(maker, parameters.lwe_dimension);
        let proto_secret_key_glwe =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        let proto_seeded_bsk = <Maker as PrototypesLweSeededBootstrapKey<
            Precision,
            InputSeededBootstrapKey::InputKeyDistribution,
            InputSeededBootstrapKey::OutputKeyDistribution,
        >>::new_lwe_seeded_bootstrap_key(
            maker,
            &proto_secret_key_lwe,
            &proto_secret_key_glwe,
            parameters.level,
            parameters.base_log,
            parameters.noise,
        );
        (proto_seeded_bsk,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_seeded_bsk,) = sample_proto;
        let synth_seeded_bsk = maker.synthesize_lwe_seeded_bootstrap_key(proto_seeded_bsk);
        (synth_seeded_bsk,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_bsk,) = context;
        let bsk = unsafe {
            engine.transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked(seeded_bsk)
        };
        (bsk,)
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
