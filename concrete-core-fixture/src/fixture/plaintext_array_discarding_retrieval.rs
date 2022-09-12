use crate::fixture::Fixture;
use crate::generation::prototyping::PrototypesPlaintextArray;
use crate::generation::synthesizing::SynthesizesPlaintextArray;
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{PlaintextCount, Variance};

use concrete_core::prelude::{PlaintextArrayDiscardingRetrievalEngine, PlaintextArrayEntity};

/// A fixture for the types implementing the `PlaintextArrayDiscardingRetrievalEngine` trait.
pub struct PlaintextArrayDiscardingRetrievalFixture;

#[derive(Debug)]
pub struct PlaintextArrayDiscardingRetrievalParameters {
    count: PlaintextCount,
}

impl<Precision, Engine, PlaintextArray> Fixture<Precision, (), Engine, (PlaintextArray,)>
    for PlaintextArrayDiscardingRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: PlaintextArrayDiscardingRetrievalEngine<PlaintextArray, Precision::Raw>,
    PlaintextArray: PlaintextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>,
{
    type Parameters = PlaintextArrayDiscardingRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        Vec<Precision::Raw>,
    );
    type PreExecutionContext = (PlaintextArray, Vec<Precision::Raw>);
    type PostExecutionContext = (PlaintextArray, Vec<Precision::Raw>);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                PlaintextArrayDiscardingRetrievalParameters {
                    count: PlaintextCount(100),
                },
                PlaintextArrayDiscardingRetrievalParameters {
                    count: PlaintextCount(1),
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
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.count.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(&raw_plaintext_array);
        let raw_output_array = Precision::Raw::zero_vec(parameters.count.0);
        (proto_plaintext_array, raw_output_array)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_plaintext_array, raw_output) = sample_proto;
        (
            maker.synthesize_plaintext_array(proto_plaintext_array),
            raw_output.to_owned(),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (plaintext, mut raw_output) = context;
        unsafe { engine.discard_retrieve_plaintext_array_unchecked(&mut raw_output, &plaintext) };
        (plaintext, raw_output)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (plaintext_array, raw_output_array) = context;
        let proto_output_plaintext_array = maker.unsynthesize_plaintext_array(plaintext_array);
        (
            maker.transform_plaintext_array_to_raw_vec(&proto_output_plaintext_array),
            raw_output_array,
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
