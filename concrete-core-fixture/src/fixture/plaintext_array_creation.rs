use crate::fixture::Fixture;
use crate::generation::prototyping::PrototypesPlaintextArray;
use crate::generation::synthesizing::SynthesizesPlaintextArray;
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{PlaintextCount, Variance};

use concrete_core::prelude::{PlaintextArrayCreationEngine, PlaintextArrayEntity};

/// A fixture for the types implementing the `PlaintextArrayCreationEngine` trait.
pub struct PlaintextArrayCreationFixture;

#[derive(Debug)]
pub struct PlaintextArrayCreationParameters {
    count: PlaintextCount,
}

impl<Precision, Engine, PlaintextArray> Fixture<Precision, (), Engine, (PlaintextArray,)>
    for PlaintextArrayCreationFixture
where
    Precision: IntegerPrecision,
    Engine: PlaintextArrayCreationEngine<Precision::Raw, PlaintextArray>,
    PlaintextArray: PlaintextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>,
{
    type Parameters = PlaintextArrayCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (Vec<Precision::Raw>,);
    type PreExecutionContext = (Vec<Precision::Raw>,);
    type PostExecutionContext = (PlaintextArray,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                PlaintextArrayCreationParameters {
                    count: PlaintextCount(1),
                },
                PlaintextArrayCreationParameters {
                    count: PlaintextCount(500),
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
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        (Precision::Raw::uniform_vec(parameters.count.0),)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        sample_proto.to_owned()
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (raw_plaintext_array,) = context;
        let plaintext_array =
            unsafe { engine.create_plaintext_array_from_unchecked(&raw_plaintext_array) };
        (plaintext_array,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (plaintext_array,) = context;
        let proto_output_plaintext = maker.unsynthesize_plaintext_array(plaintext_array);
        (
            sample_proto.0.to_owned(),
            maker.transform_plaintext_array_to_raw_vec(&proto_output_plaintext),
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (Variance(0.),)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
