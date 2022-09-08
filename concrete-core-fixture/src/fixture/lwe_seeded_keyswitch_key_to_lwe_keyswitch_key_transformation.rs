use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesLweSecretKey, PrototypesLweSeededKeyswitchKey};
use crate::generation::synthesizing::{
    SynthesizesLweKeyswitchKey, SynthesizesLweSecretKey, SynthesizesLweSeededKeyswitchKey,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension, LweKeyswitchKeyEntity,
    LweSecretKeyEntity, LweSeededKeyswitchKeyEntity,
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine, Variance,
};

/// A fixture for the types implementing the
/// `LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine` trait.
pub struct LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationFixture;

#[derive(Debug)]
pub struct LweSeededKeyswitchKeyToLweSeededKeyswitchKeyTransformationParameters {
    pub noise: Variance,
    pub lwe_dimension_in: LweDimension,
    pub lwe_dimension_out: LweDimension,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
}

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        InputSecretKey,
        OutputSecretKey,
        InputSeededKeyswitchKey,
        OutputKeyswitchKey,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (
            InputSecretKey,
            OutputSecretKey,
            InputSeededKeyswitchKey,
            OutputKeyswitchKey,
        ),
    > for LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine<
        InputSeededKeyswitchKey,
        OutputKeyswitchKey,
    >,
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: LweSecretKeyEntity,
    InputSeededKeyswitchKey: LweSeededKeyswitchKeyEntity,
    OutputKeyswitchKey: LweKeyswitchKeyEntity,
    Maker: SynthesizesLweSeededKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            InputSeededKeyswitchKey,
        > + SynthesizesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            OutputKeyswitchKey,
        > + SynthesizesLweSecretKey<Precision, InputKeyDistribution, InputSecretKey>
        + SynthesizesLweSecretKey<Precision, OutputKeyDistribution, OutputSecretKey>,
{
    type Parameters = LweSeededKeyswitchKeyToLweSeededKeyswitchKeyTransformationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesLweSeededKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::LweSeededKeyswitchKeyProto,
    );
    type PreExecutionContext = (InputSeededKeyswitchKey,);
    type PostExecutionContext = (OutputKeyswitchKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededKeyswitchKeyToLweSeededKeyswitchKeyTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension_in: LweDimension(1024),
                    lwe_dimension_out: LweDimension(630),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
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
        let proto_secret_key_in = <Maker as PrototypesLweSecretKey<
            Precision,
            InputKeyDistribution,
        >>::new_lwe_secret_key(maker, parameters.lwe_dimension_in);
        let proto_secret_key_out = <Maker as PrototypesLweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::new_lwe_secret_key(
            maker, parameters.lwe_dimension_out
        );
        let proto_seeded_ksk = <Maker as PrototypesLweSeededKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::new_lwe_seeded_keyswitch_key(
            maker,
            &proto_secret_key_in,
            &proto_secret_key_out,
            parameters.level,
            parameters.base_log,
            parameters.noise,
        );
        (proto_seeded_ksk,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_seeded_ksk,) = sample_proto;
        let synth_ksk = maker.synthesize_lwe_seeded_keyswitch_key(proto_seeded_ksk);
        (synth_ksk,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_ksk,) = context;
        let ksk = unsafe {
            engine.transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(seeded_ksk)
        };
        (ksk,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (ksk,) = context;
        maker.destroy_lwe_keyswitch_key(ksk);
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
