use concrete_core::commons::numeric::{Numeric, UnsignedInteger};
use concrete_core::prelude::{
    DispersionParameter, LogStandardDev, LweCiphertextArrayDiscardingSubtractionEngine,
    LweCiphertextArrayEntity, LweCiphertextCount, LweDimension, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextArray, PrototypesLweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::SynthesizesLweCiphertextArray;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `LweCiphertextArrayDiscardingSubtractionEngine`
/// trait.
pub struct LweCiphertextArrayDiscardingSubtractionFixture;

#[derive(Debug)]
pub struct LweCiphertextArrayDiscardingSubtractionParameters {
    pub lwe_ciphertext_count: LweCiphertextCount,
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

#[allow(clippy::type_complexity)]
impl<Precision, KeyDistribution, Engine, InputCiphertextArray, OutputCiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (InputCiphertextArray, OutputCiphertextArray)>
    for LweCiphertextArrayDiscardingSubtractionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine:
        LweCiphertextArrayDiscardingSubtractionEngine<InputCiphertextArray, OutputCiphertextArray>,
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
    Maker: SynthesizesLweCiphertextArray<Precision, KeyDistribution, InputCiphertextArray>
        + SynthesizesLweCiphertextArray<Precision, KeyDistribution, OutputCiphertextArray>,
{
    type Parameters = LweCiphertextArrayDiscardingSubtractionParameters;
    type RepetitionPrototypes =
        <Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto;
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesLweCiphertextArray<
            Precision,
            KeyDistribution,
        >>::LweCiphertextArrayProto,
        <Maker as PrototypesLweCiphertextArray<
            Precision,
            KeyDistribution,
        >>::LweCiphertextArrayProto,
        <Maker as PrototypesLweCiphertextArray<
            Precision,
            KeyDistribution,
        >>::LweCiphertextArrayProto,
    );
    type PreExecutionContext = (
        InputCiphertextArray,
        InputCiphertextArray,
        OutputCiphertextArray,
    );
    type PostExecutionContext = (
        InputCiphertextArray,
        InputCiphertextArray,
        OutputCiphertextArray,
    );
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextArrayDiscardingSubtractionParameters {
                    lwe_ciphertext_count: LweCiphertextCount(1),
                    noise: Variance(LogStandardDev::from_log_standard_dev(-15.).get_variance()),
                    lwe_dimension: LweDimension(600),
                },
                LweCiphertextArrayDiscardingSubtractionParameters {
                    lwe_ciphertext_count: LweCiphertextCount(100),
                    noise: Variance(LogStandardDev::from_log_standard_dev(-15.).get_variance()),
                    lwe_dimension: LweDimension(600),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        maker.new_lwe_secret_key(parameters.lwe_dimension)
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let proto_secret_key = repetition_proto;
        let raw_plaintext_array1 = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let raw_plaintext_array2 = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_array1 =
            maker.transform_raw_vec_to_plaintext_array(&raw_plaintext_array1);
        let proto_plaintext_array2 =
            maker.transform_raw_vec_to_plaintext_array(&raw_plaintext_array2);
        let proto_input_ciphertext_array1 = maker.encrypt_plaintext_array_to_lwe_ciphertext_array(
            proto_secret_key,
            &proto_plaintext_array1,
            parameters.noise,
        );
        let proto_input_ciphertext_array2 = maker.encrypt_plaintext_array_to_lwe_ciphertext_array(
            proto_secret_key,
            &proto_plaintext_array2,
            parameters.noise,
        );
        let proto_output_ciphertext_array = maker.trivially_encrypt_zeros_to_lwe_ciphertext_array(
            parameters.lwe_dimension,
            parameters.lwe_ciphertext_count,
        );
        (
            proto_plaintext_array1,
            proto_plaintext_array2,
            proto_input_ciphertext_array1,
            proto_input_ciphertext_array2,
            proto_output_ciphertext_array,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (
            _,
            _,
            proto_input_ciphertext_array1,
            proto_input_ciphertext_array2,
            proto_output_ciphertext_array,
        ) = sample_proto;
        let synth_input_ciphertext_array1 =
            maker.synthesize_lwe_ciphertext_array(proto_input_ciphertext_array1);
        let synth_input_ciphertext_array2 =
            maker.synthesize_lwe_ciphertext_array(proto_input_ciphertext_array2);
        let synth_output_ciphertext_array =
            maker.synthesize_lwe_ciphertext_array(proto_output_ciphertext_array);
        (
            synth_input_ciphertext_array1,
            synth_input_ciphertext_array2,
            synth_output_ciphertext_array,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (input_ciphertext_array1, input_ciphertext_array2, mut output_ciphertext_array) =
            context;
        unsafe {
            engine.discard_sub_lwe_ciphertext_array_unchecked(
                &mut output_ciphertext_array,
                &input_ciphertext_array1,
                &input_ciphertext_array2,
            )
        };
        (
            input_ciphertext_array1,
            input_ciphertext_array2,
            output_ciphertext_array,
        )
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (input_ciphertext_array1, input_ciphertext_array2, output_ciphertext_array) = context;
        let (proto_plaintext_array1, proto_plaintext_array2, ..) = sample_proto;
        let proto_secret_key = repetition_proto;
        let raw_plaintext_array1 =
            maker.transform_plaintext_array_to_raw_vec(proto_plaintext_array1);
        let raw_plaintext_array2 =
            maker.transform_plaintext_array_to_raw_vec(proto_plaintext_array2);
        let predicted_output = raw_plaintext_array1
            .iter()
            .zip(raw_plaintext_array2.iter())
            .map(|(&a, &b)| a.wrapping_sub(b))
            .collect();
        let proto_output_ciphertext_array =
            maker.unsynthesize_lwe_ciphertext_array(output_ciphertext_array);
        let proto_output_plaintext_array = maker.decrypt_lwe_ciphertext_array_to_plaintext_array(
            proto_secret_key,
            &proto_output_ciphertext_array,
        );
        maker.destroy_lwe_ciphertext_array(input_ciphertext_array1);
        maker.destroy_lwe_ciphertext_array(input_ciphertext_array2);
        (
            predicted_output,
            maker.transform_plaintext_array_to_raw_vec(&proto_output_plaintext_array),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let predicted_variance: Variance = concrete_npe::estimate_addition_noise::<_, _>(
            parameters.noise,
            parameters.noise,
            Precision::Raw::BITS as u32,
        );
        (predicted_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
