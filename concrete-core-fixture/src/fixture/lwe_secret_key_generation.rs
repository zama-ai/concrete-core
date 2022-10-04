use crate::fixture::Fixture;
use crate::generation::synthesizing::SynthesizesLweSecretKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_core::prelude::{LweDimension, LweSecretKeyEntity, LweSecretKeyGenerationEngine};

/// A fixture for the types implementing the `LweSecretKeyGenerationEngine` trait.
pub struct LweSecretKeyGenerationFixture;

#[derive(Debug)]
pub struct LweSecretKeyGenerationParameters {
    pub lwe_dimension: LweDimension,
}

impl<Precision, KeyDistribution, Engine, SecretKey>
    Fixture<Precision, (KeyDistribution,), Engine, (SecretKey,)> for LweSecretKeyGenerationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweSecretKeyGenerationEngine<SecretKey>,
    SecretKey: LweSecretKeyEntity,
    Maker: SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>,
{
    type Parameters = LweSecretKeyGenerationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = ();
    type PreExecutionContext = ();
    type PostExecutionContext = (SecretKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![LweSecretKeyGenerationParameters {
                lwe_dimension: LweDimension(630),
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
        let sk = unsafe { engine.generate_new_lwe_secret_key_unchecked(parameters.lwe_dimension) };
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
        maker.destroy_lwe_secret_key(sk);
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(
        _parameters: &Self::Parameters,
        _criteria: &Self::Criteria,
        _outputs: &[Self::Outcome],
    ) -> bool {
        // The test to verify the generated key is not yet implemented.
        false
    }
}
