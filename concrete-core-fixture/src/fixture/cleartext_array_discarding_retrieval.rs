use crate::fixture::Fixture;
use crate::generation::prototyping::PrototypesCleartextArray;
use crate::generation::synthesizing::SynthesizesCleartextArray;
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{CleartextCount, Variance};

use concrete_core::prelude::{CleartextArrayDiscardingRetrievalEngine, CleartextArrayEntity};

/// A fixture for the types implementing the `CleartextArrayDiscardingRetrievalEngine` trait.
pub struct CleartextArrayDiscardingRetrievalFixture;

#[derive(Debug)]
pub struct CleartextArrayDiscardingRetrievalParameters {
    count: CleartextCount,
}

impl<Precision, Engine, CleartextArray> Fixture<Precision, (), Engine, (CleartextArray,)>
    for CleartextArrayDiscardingRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: CleartextArrayDiscardingRetrievalEngine<CleartextArray, Precision::Raw>,
    CleartextArray: CleartextArrayEntity,
    Maker: SynthesizesCleartextArray<Precision, CleartextArray>,
{
    type Parameters = CleartextArrayDiscardingRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesCleartextArray<Precision>>::CleartextArrayProto,
        Vec<Precision::Raw>,
    );
    type PreExecutionContext = (CleartextArray, Vec<Precision::Raw>);
    type PostExecutionContext = (CleartextArray, Vec<Precision::Raw>);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                CleartextArrayDiscardingRetrievalParameters {
                    count: CleartextCount(100),
                },
                CleartextArrayDiscardingRetrievalParameters {
                    count: CleartextCount(1),
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
        let raw_cleartext_array = Precision::Raw::uniform_vec(parameters.count.0);
        let proto_cleartext_array =
            maker.transform_raw_vec_to_cleartext_array(&raw_cleartext_array);
        let raw_output_array = Precision::Raw::zero_vec(parameters.count.0);
        (proto_cleartext_array, raw_output_array)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_cleartext_array, raw_output) = sample_proto;
        (
            maker.synthesize_cleartext_array(proto_cleartext_array),
            raw_output.to_owned(),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (cleartext, mut raw_output) = context;
        unsafe { engine.discard_retrieve_cleartext_array_unchecked(&mut raw_output, &cleartext) };
        (cleartext, raw_output)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (cleartext_array, raw_output_array) = context;
        let proto_output_cleartext_array = maker.unsynthesize_cleartext_array(cleartext_array);
        (
            maker.transform_cleartext_array_to_raw_vec(&proto_output_cleartext_array),
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
