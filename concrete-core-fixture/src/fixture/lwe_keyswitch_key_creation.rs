use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesContainer, PrototypesLweKeyswitchKey};
use crate::generation::synthesizing::{SynthesizesContainer, SynthesizesLweKeyswitchKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension, LweKeyswitchKeyCreationEngine,
    LweKeyswitchKeyEntity,
};

/// A fixture for the types implementing the `LweKeyswitchKeyCreationEngine` trait.
pub struct LweKeyswitchKeyCreationFixture;

#[derive(Debug)]
pub struct LweKeyswitchKeyCreationParameters {
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
}

impl<Precision, InputKeyDistribution, OutputKeyDistribution, Engine, Container, KeyswitchKey>
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (Container, KeyswitchKey),
    > for LweKeyswitchKeyCreationFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweKeyswitchKeyCreationEngine<Container, KeyswitchKey>,
    KeyswitchKey: LweKeyswitchKeyEntity,
    Maker: SynthesizesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            KeyswitchKey,
        > + SynthesizesContainer<Precision, Container>,
{
    type Parameters = LweKeyswitchKeyCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (<Maker as PrototypesContainer<Precision>>::ContainerProto,);
    type PreExecutionContext = (Container,);
    type PostExecutionContext = (KeyswitchKey,);
    type Criteria = ();
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            // These parameters are not realistic but as we are just testing container copy/move
            // we would just multiply the amount of data for no real benefit
            vec![LweKeyswitchKeyCreationParameters {
                input_lwe_dimension: LweDimension(20),
                output_lwe_dimension: LweDimension(10),
                level: DecompositionLevelCount(3),
                base_log: DecompositionBaseLog(7),
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
        (maker.transform_raw_vec_to_container(&Precision::Raw::uniform_vec(num_elements)),)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        (maker.synthesize_container(&sample_proto.0),)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (underlying_container,) = context;
        let lwe_keyswitch_key = unsafe {
            engine.create_lwe_keyswitch_key_from_unchecked(
                underlying_container,
                parameters.output_lwe_dimension,
                parameters.base_log,
                parameters.level,
            )
        };
        (lwe_keyswitch_key,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (lwe_keyswitch_key,) = context;
        let ksk_proto = maker.unsynthesize_lwe_keyswitch_key(lwe_keyswitch_key);
        (
            maker.transform_container_to_raw_vec(&sample_proto.0),
            maker.transform_lwe_keyswitch_key_to_raw_vec(&ksk_proto),
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
        // The test to verify the generated key is not yet implemented.
        let (sample, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        sample == actual
    }
}
