use crate::fixture::Fixture;
use crate::generation::prototyping::PrototypesCleartextArray;
use crate::generation::synthesizing::SynthesizesCleartextArray;
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{CleartextCount, Variance};

use concrete_core::prelude::{CleartextArrayEntity, CleartextArrayRetrievalEngine};

/// A fixture for the types implementing the `CleartextArrayRetrievalEngine` trait.
pub struct CleartextArrayRetrievalFixture;

#[derive(Debug)]
pub struct CleartextArrayRetrievalParameters {
    count: CleartextCount,
}

impl<Precision, Engine, CleartextArray> Fixture<Precision, (), Engine, (CleartextArray,)>
    for CleartextArrayRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: CleartextArrayRetrievalEngine<CleartextArray, Precision::Raw>,
    CleartextArray: CleartextArrayEntity,
    Maker: SynthesizesCleartextArray<Precision, CleartextArray>,
{
    type Parameters = CleartextArrayRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (<Maker as PrototypesCleartextArray<Precision>>::CleartextArrayProto,);
    type PreExecutionContext = (CleartextArray,);
    type PostExecutionContext = (CleartextArray, Vec<Precision::Raw>);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                CleartextArrayRetrievalParameters {
                    count: CleartextCount(100),
                },
                CleartextArrayRetrievalParameters {
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
        (proto_cleartext_array,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_cleartext_array,) = sample_proto;
        (maker.synthesize_cleartext_array(proto_cleartext_array),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (cleartext_array,) = context;
        let raw_output_array =
            unsafe { engine.retrieve_cleartext_array_unchecked(&cleartext_array) };
        (cleartext_array, raw_output_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (cleartext_array, raw_output_array) = context;
        let proto_output_cleartext = maker.unsynthesize_cleartext_array(cleartext_array);
        (
            maker.transform_cleartext_array_to_raw_vec(&proto_output_cleartext),
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
