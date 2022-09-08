use crate::fixture::{fix_estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms, Fixture};
use crate::generation::prototyping::{
    PrototypesLweCiphertextVector, PrototypesLweKeyswitchKey, PrototypesLweSecretKey,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{SynthesizesLweCiphertextVector, SynthesizesLweKeyswitchKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, DispersionParameter, LogStandardDev,
    LweCiphertextCount, LweCiphertextVectorDiscardingKeyswitchEngine, LweCiphertextVectorEntity,
    LweDimension, LweKeyswitchKeyEntity, Variance,
};

/// A fixture for the types implementing the `LweCiphertextVectorDiscardingKeyswitchEngine` trait.
pub struct LweCiphertextVectorDiscardingKeyswitchFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorDiscardingKeyswitchParameters {
    pub n_bit_msg: usize,
    pub input_noise: Variance,
    pub ksk_noise: Variance,
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub decomp_level_count: DecompositionLevelCount,
    pub decomp_base_log: DecompositionBaseLog,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        KeyswitchKey,
        InputCiphertextVector,
        OutputCiphertextVector,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (KeyswitchKey, InputCiphertextVector, OutputCiphertextVector),
    > for LweCiphertextVectorDiscardingKeyswitchFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextVectorDiscardingKeyswitchEngine<
        KeyswitchKey,
        InputCiphertextVector,
        OutputCiphertextVector,
    >,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    KeyswitchKey: LweKeyswitchKeyEntity,
    Maker: SynthesizesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            KeyswitchKey,
        > + SynthesizesLweCiphertextVector<Precision, InputKeyDistribution, InputCiphertextVector>
        + SynthesizesLweCiphertextVector<Precision, OutputKeyDistribution, OutputCiphertextVector>,
{
    type Parameters = LweCiphertextVectorDiscardingKeyswitchParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesLweSecretKey<Precision, OutputKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesLweKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::LweKeyswitchKeyProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            InputKeyDistribution,
        >>::LweCiphertextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputKeyDistribution,
        >>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (OutputCiphertextVector, InputCiphertextVector, KeyswitchKey);
    type PostExecutionContext = (OutputCiphertextVector, InputCiphertextVector, KeyswitchKey);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorDiscardingKeyswitchParameters {
                    n_bit_msg: 8,
                    input_noise: Variance(
                        LogStandardDev::from_log_standard_dev(-10.).get_variance(),
                    ),
                    ksk_noise: Variance(LogStandardDev::from_log_standard_dev(-25.).get_variance()),
                    input_lwe_dimension: LweDimension(600),
                    output_lwe_dimension: LweDimension(1024),
                    decomp_level_count: DecompositionLevelCount(8),
                    decomp_base_log: DecompositionBaseLog(3),
                    lwe_ciphertext_count: LweCiphertextCount(10),
                },
                LweCiphertextVectorDiscardingKeyswitchParameters {
                    n_bit_msg: 8,
                    input_noise: Variance(
                        LogStandardDev::from_log_standard_dev(-10.).get_variance(),
                    ),
                    ksk_noise: Variance(LogStandardDev::from_log_standard_dev(-25.).get_variance()),
                    input_lwe_dimension: LweDimension(600),
                    output_lwe_dimension: LweDimension(1024),
                    decomp_level_count: DecompositionLevelCount(8),
                    decomp_base_log: DecompositionBaseLog(3),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_output_secret_key = <Maker as PrototypesLweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::new_lwe_secret_key(
            maker, parameters.output_lwe_dimension
        );
        let proto_input_secret_key =
            <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::new_lwe_secret_key(
                maker,
                parameters.input_lwe_dimension,
            );
        let proto_keyswitch_key = maker.new_lwe_keyswitch_key(
            &proto_input_secret_key,
            &proto_output_secret_key,
            parameters.decomp_level_count,
            parameters.decomp_base_log,
            parameters.ksk_noise,
        );
        (
            proto_input_secret_key,
            proto_output_secret_key,
            proto_keyswitch_key,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_input_secret_key, ..) = repetition_proto;
        let raw_plaintext_vector = Precision::Raw::uniform_n_msb_vec(
            parameters.n_bit_msg,
            parameters.lwe_ciphertext_count.0,
        );
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector);
        let proto_input_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            InputKeyDistribution,
        >>::encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            maker,
            proto_input_secret_key,
            &proto_plaintext_vector,
            parameters.input_noise,
        );
        let proto_output_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputKeyDistribution,
        >>::trivially_encrypt_zeros_to_lwe_ciphertext_vector(
            maker,
            parameters.output_lwe_dimension,
            parameters.lwe_ciphertext_count,
        );
        (
            proto_plaintext_vector,
            proto_input_ciphertext_vector,
            proto_output_ciphertext_vector,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, _, proto_keyswitch_key) = repetition_proto;
        let (_, proto_input_ciphertext_vector, proto_output_ciphertext_vector) = sample_proto;
        let synth_keywsitch_key = maker.synthesize_lwe_keyswitch_key(proto_keyswitch_key);
        let synth_input_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_input_ciphertext_vector);
        let synth_output_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_output_ciphertext_vector);
        (
            synth_output_ciphertext_vector,
            synth_input_ciphertext_vector,
            synth_keywsitch_key,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (mut output_ciphertext_vector, input_ciphertext_vector, keyswitch_key) = context;
        unsafe {
            engine.discard_keyswitch_lwe_ciphertext_vector_unchecked(
                &mut output_ciphertext_vector,
                &input_ciphertext_vector,
                &keyswitch_key,
            )
        };
        (
            output_ciphertext_vector,
            input_ciphertext_vector,
            keyswitch_key,
        )
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (output_ciphertext_vector, input_ciphertext_vector, keyswitch_key) = context;
        let (_, proto_output_secret_key, _) = repetition_proto;
        let (proto_plaintext_vector, ..) = sample_proto;
        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(output_ciphertext_vector);
        let proto_output_plaintext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputKeyDistribution,
        >>::decrypt_lwe_ciphertext_vector_to_plaintext_vector(
            maker,
            proto_output_secret_key,
            &proto_output_ciphertext_vector,
        );
        maker.destroy_lwe_ciphertext_vector(input_ciphertext_vector);
        maker.destroy_lwe_keyswitch_key(keyswitch_key);
        (
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector),
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let predicted_variance: Variance =
            fix_estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
                Precision::Raw,
                _,
                _,
                OutputKeyDistribution,
            >(
                parameters.input_lwe_dimension,
                parameters.input_noise,
                parameters.ksk_noise,
                parameters.decomp_base_log,
                parameters.decomp_level_count,
            );
        (predicted_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
