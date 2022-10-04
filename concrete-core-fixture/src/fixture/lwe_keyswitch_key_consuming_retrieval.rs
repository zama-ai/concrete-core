use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesContainer, PrototypesLweKeyswitchKey};
use crate::generation::synthesizing::{SynthesizesContainer, SynthesizesLweKeyswitchKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use concrete_core::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};

use concrete_core::prelude::{LweKeyswitchKeyConsumingRetrievalEngine, LweKeyswitchKeyEntity};

#[derive(Debug)]
pub struct LweKeyswitchKeyConsumingRetrievalParameters {
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
}

/// A fixture for the types implementing the `LweKeyswitchKeyConsumingRetrievalEngine` trait with
/// LWE keyswitch key.
pub struct LweKeyswitchKeyConsumingRetrievalFixture;

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        LweKeyswitchKey,
        Container,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (LweKeyswitchKey, Container),
    > for LweKeyswitchKeyConsumingRetrievalFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweKeyswitchKeyConsumingRetrievalEngine<LweKeyswitchKey, Container>,
    LweKeyswitchKey: LweKeyswitchKeyEntity,
    Maker: SynthesizesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            LweKeyswitchKey,
        > + SynthesizesContainer<Precision, Container>,
{
    type Parameters = LweKeyswitchKeyConsumingRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::LweKeyswitchKeyProto,
    );
    type PreExecutionContext = (LweKeyswitchKey,);
    type PostExecutionContext = (Container,);
    type Criteria = ();
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![LweKeyswitchKeyConsumingRetrievalParameters {
                input_lwe_dimension: LweDimension(20),
                output_lwe_dimension: LweDimension(10),
                level: DecompositionLevelCount(2),
                base_log: DecompositionBaseLog(1),
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
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let num_elements = parameters.input_lwe_dimension.0
            * parameters.output_lwe_dimension.to_lwe_size().0
            * parameters.level.0;
        let ksk_proto = maker.transform_raw_vec_to_lwe_keyswitch_key(
            &Precision::Raw::uniform_vec(num_elements),
            parameters.output_lwe_dimension,
            parameters.level,
            parameters.base_log,
        );
        (ksk_proto,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ksk,) = sample_proto;
        (maker.synthesize_lwe_keyswitch_key(proto_ksk),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (ksk,) = context;
        let raw_ksk = unsafe { engine.consume_retrieve_lwe_keyswitch_key_unchecked(ksk) };
        (raw_ksk,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_ksk,) = sample_proto;
        let (raw_ksk,) = context;
        let proto_container = maker.unsynthesize_container(raw_ksk);
        (
            maker.transform_lwe_keyswitch_key_to_raw_vec(proto_ksk),
            maker.transform_container_to_raw_vec(&proto_container),
        )
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
        outputs: &[Self::Outcome],
    ) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        means == actual
    }
}
