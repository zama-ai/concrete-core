use crate::fixture::Fixture;
use crate::generation::synthesizing::SynthesizesGlweSecretKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::{GlweSecretKeyEntity, GlweSecretKeyGenerationEngine};

/// A fixture for the types implementing the `GlweSecretKeyGenerationEngine` trait.
pub struct GlweSecretKeyGenerationFixture;

#[derive(Debug)]
pub struct GlweSecretKeyGenerationParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, KeyDistribution, Engine, SecretKey>
    Fixture<Precision, (KeyDistribution,), Engine, (SecretKey,)> for GlweSecretKeyGenerationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,

    Engine: GlweSecretKeyGenerationEngine<SecretKey>,
    SecretKey: GlweSecretKeyEntity,
    Maker: SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>,
{
    type Parameters = GlweSecretKeyGenerationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = ();
    type PreExecutionContext = ();
    type PostExecutionContext = (SecretKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![GlweSecretKeyGenerationParameters {
                glwe_dimension: GlweDimension(1),
                polynomial_size: PolynomialSize(1024),
            }]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
    }

    fn generate_random_sample_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        _context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let sk = unsafe {
            engine.generate_new_glwe_secret_key_unchecked(
                parameters.glwe_dimension,
                parameters.polynomial_size,
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
        let (sk,) = context;
        maker.destroy_glwe_secret_key(sk);
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
