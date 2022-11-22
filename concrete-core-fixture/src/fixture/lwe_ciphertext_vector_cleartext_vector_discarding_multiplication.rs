use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesCleartextVector, PrototypesLweCiphertextVector, PrototypesLweSecretKey,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{SynthesizesCleartextVector, SynthesizesLweCiphertextVector};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::commons::numeric::UnsignedInteger;
use concrete_core::prelude::{
    CleartextVectorEntity, DispersionParameter, LogStandardDev, LweCiphertextCount,
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine, LweCiphertextVectorEntity,
    LweDimension, Variance,
};

/// A fixture for the types implementing the
/// `LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine` trait.
pub struct LweCiphertextVectorCleartextVectorDiscardingMultiplicationFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorCleartextVectorDiscardingMultiplicationParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_count: LweCiphertextCount,
}

#[allow(clippy::type_complexity)]
impl<Precision, KeyDistribution, Engine, InputCiphertext, CleartextVector, OutputCiphertext>
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (InputCiphertext, CleartextVector, OutputCiphertext),
    > for LweCiphertextVectorCleartextVectorDiscardingMultiplicationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine<
        InputCiphertext,
        CleartextVector,
        OutputCiphertext,
    >,
    InputCiphertext: LweCiphertextVectorEntity,
    CleartextVector: CleartextVectorEntity,
    OutputCiphertext: LweCiphertextVectorEntity,
    Maker: SynthesizesCleartextVector<Precision, CleartextVector>
        + SynthesizesLweCiphertextVector<Precision, KeyDistribution, InputCiphertext>
        + SynthesizesLweCiphertextVector<Precision, KeyDistribution, OutputCiphertext>,
{
    type Parameters = LweCiphertextVectorCleartextVectorDiscardingMultiplicationParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesCleartextVector<Precision>>::CleartextVectorProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesLweCiphertextVector<Precision, KeyDistribution>>::LweCiphertextVectorProto,
        <Maker as PrototypesLweCiphertextVector<Precision, KeyDistribution>>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (InputCiphertext, CleartextVector, OutputCiphertext);
    type PostExecutionContext = (InputCiphertext, CleartextVector, OutputCiphertext);
    type Criteria = (Vec<Variance>,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorCleartextVectorDiscardingMultiplicationParameters {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-50.).get_variance()),
                    lwe_dimension: LweDimension(200),
                    lwe_count: LweCiphertextCount(1),
                },
                LweCiphertextVectorCleartextVectorDiscardingMultiplicationParameters {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-50.).get_variance()),
                    lwe_dimension: LweDimension(200),
                    lwe_count: LweCiphertextCount(1000),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key = maker.new_lwe_secret_key(parameters.lwe_dimension);
        let raw_cleartext_vector =
            Precision::Raw::uniform_zero_centered_vec(1024, parameters.lwe_count.0);
        let proto_cleartext_vector =
            maker.transform_raw_vec_to_cleartext_vector(&raw_cleartext_vector);
        (proto_secret_key, proto_cleartext_vector)
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_secret_key, _) = repetition_proto;
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.lwe_count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector);
        let proto_input_ciphertext = maker.encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            proto_secret_key,
            &proto_plaintext_vector,
            parameters.noise,
        );
        let proto_output_ciphertext = maker.trivially_encrypt_zeros_to_lwe_ciphertext_vector(
            parameters.lwe_dimension,
            parameters.lwe_count,
        );
        (
            proto_plaintext_vector,
            proto_input_ciphertext,
            proto_output_ciphertext,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, proto_cleartext_vector) = repetition_proto;
        let (_, proto_input_ciphertext, proto_output_ciphertext) = sample_proto;
        let synth_input_ciphertext = maker.synthesize_lwe_ciphertext_vector(proto_input_ciphertext);
        let synth_cleartext_vector = maker.synthesize_cleartext_vector(proto_cleartext_vector);
        let synth_output_ciphertext =
            maker.synthesize_lwe_ciphertext_vector(proto_output_ciphertext);
        (
            synth_input_ciphertext,
            synth_cleartext_vector,
            synth_output_ciphertext,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (input_ciphertext, cleartext_vector, mut output_ciphertext) = context;
        unsafe {
            engine.discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
                &mut output_ciphertext,
                &input_ciphertext,
                &cleartext_vector,
            )
        };
        (input_ciphertext, cleartext_vector, output_ciphertext)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (input_ciphertext_vector, cleartext_vector, output_ciphertext_vector) = context;
        let (proto_plaintext_vector, ..) = sample_proto;
        let (proto_secret_key, proto_cleartext_vector) = repetition_proto;
        let raw_plaintext_vector =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector);
        let raw_cleartext_vector =
            maker.transform_cleartext_vector_to_raw_vec(proto_cleartext_vector);
        let expected_mean = raw_plaintext_vector
            .iter()
            .zip(raw_cleartext_vector.iter())
            .map(|(&a, &b)| a.wrapping_mul(b))
            .collect();
        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(output_ciphertext_vector);
        let proto_output_plaintext_vector = maker
            .decrypt_lwe_ciphertext_vector_to_plaintext_vector(
                proto_secret_key,
                &proto_output_ciphertext_vector,
            );
        maker.destroy_lwe_ciphertext_vector(input_ciphertext_vector);
        maker.destroy_cleartext_vector(cleartext_vector);
        (
            expected_mean,
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let (_, proto_cleartext_vector) = repetition_proto;
        let raw_cleartext_vector =
            maker.transform_cleartext_vector_to_raw_vec(proto_cleartext_vector);
        let mut predicted_variance: Vec<Variance> = Vec::with_capacity(parameters.lwe_count.0);
        for c in raw_cleartext_vector {
            predicted_variance.push(
                concrete_npe::estimate_integer_plaintext_multiplication_noise::<Precision::Raw, _>(
                    parameters.noise,
                    c,
                ),
            );
        }
        (predicted_variance,)
    }

    fn verify(
        parameters: &Self::Parameters,
        criteria: &Self::Criteria,
        outputs: &[Self::Outcome],
    ) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        let mut result = false;
        // For each cleartext, we have to check the output distribution
        for p in 0..parameters.lwe_count.0 {
            // These are lwe_count * SAMPLE_SIZE outputs
            // for each p we take SAMPLE_SIZE and check the result
            let mut m: Vec<Precision::Raw> =
                Vec::with_capacity(means.len() / parameters.lwe_count.0);
            let mut a: Vec<Precision::Raw> =
                Vec::with_capacity(actual.len() / parameters.lwe_count.0);
            for ((n, x), y) in means.iter().enumerate().zip(actual.iter()) {
                if (n - p) % parameters.lwe_count.0 == 0 {
                    m.push(*x);
                    a.push(*y);
                }
            }
            let c = criteria.0.get(p).unwrap();
            result = assert_noise_distribution(a.as_slice(), m.as_slice(), *c);
        }
        result
    }
}
