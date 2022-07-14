use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesStandardRelinearizationKey, PrototypesGlweSecretKey};
use crate::generation::synthesizing::{
    SynthesizesGlweSecretKey, SynthesizesGlweRelinearizationKey,
};
use crate::generation::{IntegerPrecision, Maker};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, LweDimension};
use concrete_core::prelude::{
    GlweSecretKeyEntity, GlweRelinearizationKeyCreationEngine, GlweRelinearizationKeyEntity,
};

/// A fixture for the types implementing the `GlweRelinearizationKeyCreationEngine` trait.
pub struct GlweRelinearizationKeyCreationFixture;

#[derive(Debug)]
pub struct GlweRelinearizationKeyCreationParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
    pub noise: Variance,
}

impl<Precision, Engine, GlweSecretKey, GlweRelinearizationKey>
Fixture<Precision, Engine, (GlweSecretKey, GlweRelinearizationKey)>
for GlweRelinearizationKeyCreationFixture
    where
        Precision: IntegerPrecision,
        Engine: GlweRelinearizationKeyCreationEngine<GlweSecretKey, GlweRelinearizationKey>,
        GlweSecretKey: GlweSecretKeyEntity,
        GlweRelinearizationKey: GlweRelinearizationKeyEntity<
            InputKeyDistribution = GlweSecretKey::KeyDistribution,
            OutputKeyDistribution = GlweRelinearizationKey::KeyDistribution,
        >,
        Maker: SynthesizesGlweRelinearizationKey<Precision, GlweSecretKey>
        + SynthesizesGlweSecretKey<Precision, GlweSecretKey>
{
    type Parameters = GlweRelinearizationKeyCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesStandardRelinearizationKey<Precision, GlweSecretKey::KeyDistribution,GlweRelinearizationKey>>::StandardRelinearizationKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, GlweSecretKey::KeyDistribution>>::GlweSecretKeyProto,
    );
    type PreExecutionContext = (GlweSecretKey,);
    type PostExecutionContext = (GlweRelinearizationKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweRelinearizationKeyCreationParameters {
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(1024),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
                    noise: Variance(0.00000001),
                },
                GlweRelinearizationKeyCreationParameters {
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
        let proto_secret_key_glwe =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        (proto_secret_key_glwe)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key_lwe, proto_secret_key_glwe) = sample_proto;
        let synth_secret_key_glwe = maker.synthesize_glwe_secret_key(proto_secret_key_glwe);
        (synth_secret_key_glwe)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (sk_in) = context;
        let rlk = unsafe {
            engine.create_glwe_relinearization_key_unchecked(
                &sk_in,
                parameters.base_log,
                parameters.level,
                parameters.noise,
            )
        };
        (rlk,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (rlk,) = context;
        maker.destroy_glwe_relinearization_key(rlk);
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
