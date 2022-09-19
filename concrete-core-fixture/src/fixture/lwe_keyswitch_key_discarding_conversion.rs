use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesLweKeyswitchKey, PrototypesLweSecretKey};
use crate::generation::synthesizing::SynthesizesLweKeyswitchKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    LweKeyswitchKeyDiscardingConversionEngine, LweKeyswitchKeyEntity, Variance,
};

/// A fixture for the types implementing the `LweKeyswitchKeyDiscardingConversionEngine` trait.
pub struct LweKeyswitchKeyDiscardingConversionFixture;

#[derive(Debug)]
pub struct LweKeyswitchKeyDiscardingConversionParameters {
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
    pub noise: Variance,
}

impl<Precision, InputKeyDistribution, OutputKeyDistribution, Engine, InputKey, OutputKey>
    Fixture<Precision, (InputKeyDistribution, OutputKeyDistribution), Engine, (InputKey, OutputKey)>
    for LweKeyswitchKeyDiscardingConversionFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweKeyswitchKeyDiscardingConversionEngine<InputKey, OutputKey>,
    InputKey: LweKeyswitchKeyEntity,
    OutputKey: LweKeyswitchKeyEntity,
    Maker: SynthesizesLweKeyswitchKey<Precision, InputKeyDistribution, OutputKeyDistribution, InputKey>
        + SynthesizesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            OutputKey,
        >,
{
    type Parameters = LweKeyswitchKeyDiscardingConversionParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::LweKeyswitchKeyProto,
        <Maker as PrototypesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::LweKeyswitchKeyProto,
    );
    type SamplePrototypes = ();
    type PreExecutionContext = (InputKey, OutputKey);
    type PostExecutionContext = (OutputKey,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![LweKeyswitchKeyDiscardingConversionParameters {
                input_lwe_dimension: LweDimension(20),
                output_lwe_dimension: LweDimension(10),
                level: DecompositionLevelCount(3),
                base_log: DecompositionBaseLog(7),
                noise: Variance(0.00000001),
            }]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let input_key =
            <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::new_lwe_secret_key(
                maker,
                parameters.input_lwe_dimension,
            );
        let output_key =
            <Maker as PrototypesLweSecretKey<Precision, OutputKeyDistribution>>::new_lwe_secret_key(
                maker,
                parameters.output_lwe_dimension,
            );
        let proto_ksk_in = maker.new_lwe_keyswitch_key(
            &input_key,
            &output_key,
            parameters.level,
            parameters.base_log,
            parameters.noise,
        );
        let proto_ksk_out = maker.new_lwe_keyswitch_key(
            &input_key,
            &output_key,
            parameters.level,
            parameters.base_log,
            parameters.noise,
        );
        (proto_ksk_in, proto_ksk_out)
    }

    fn generate_random_sample_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ksk_in, proto_ksk_out) = repetition_proto;
        let synth_ksk_in = maker.synthesize_lwe_keyswitch_key(proto_ksk_in);
        let synth_ksk_out = maker.synthesize_lwe_keyswitch_key(proto_ksk_out);
        (synth_ksk_in, synth_ksk_out)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (ksk_in, mut ksk_out) = context;
        unsafe { engine.discard_convert_lwe_keyswitch_key_unchecked(&mut ksk_out, &ksk_in) };
        (ksk_out,)
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
