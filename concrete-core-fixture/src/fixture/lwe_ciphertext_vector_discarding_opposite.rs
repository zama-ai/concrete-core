use concrete_core::commons::numeric::UnsignedInteger;
use concrete_core::prelude::{
    DispersionParameter, LogStandardDev, LweCiphertextCount,
    LweCiphertextVectorDiscardingOppositeEngine, LweCiphertextVectorEntity, LweDimension, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::SynthesizesLweCiphertextVector;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `LweCiphertextVectorDiscardingOppositeEngine`
/// trait.
pub struct LweCiphertextVectorDiscardingOppositeFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorDiscardingOppositeParameters {
    pub lwe_ciphertext_count: LweCiphertextCount,
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

#[allow(clippy::type_complexity)]
impl<Precision, KeyDistribution, Engine, InputCiphertextVector, OutputCiphertextVector>
    Fixture<Precision, (KeyDistribution,), Engine, (InputCiphertextVector, OutputCiphertextVector)>
    for LweCiphertextVectorDiscardingOppositeFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine:
        LweCiphertextVectorDiscardingOppositeEngine<InputCiphertextVector, OutputCiphertextVector>,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    Maker: SynthesizesLweCiphertextVector<Precision, KeyDistribution, InputCiphertextVector>
        + SynthesizesLweCiphertextVector<Precision, KeyDistribution, OutputCiphertextVector>,
{
    type Parameters = LweCiphertextVectorDiscardingOppositeParameters;
    type RepetitionPrototypes =
        <Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto;
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            KeyDistribution,
        >>::LweCiphertextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            KeyDistribution,
        >>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (InputCiphertextVector, OutputCiphertextVector);
    type PostExecutionContext = (InputCiphertextVector, OutputCiphertextVector);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![LweCiphertextVectorDiscardingOppositeParameters {
                lwe_ciphertext_count: LweCiphertextCount(1),
                noise: Variance(LogStandardDev::from_log_standard_dev(-15.).get_variance()),
                lwe_dimension: LweDimension(60),
            }]
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
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector);
        let proto_input_ciphertext_vector = maker
            .encrypt_plaintext_vector_to_lwe_ciphertext_vector(
                proto_secret_key,
                &proto_plaintext_vector,
                parameters.noise,
            );
        let proto_output_ciphertext_vector = maker
            .trivially_encrypt_zeros_to_lwe_ciphertext_vector(
                parameters.lwe_dimension,
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
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, proto_input_ciphertext_vector, proto_output_ciphertext_vector) = sample_proto;
        let synth_input_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_input_ciphertext_vector);
        let synth_output_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_output_ciphertext_vector);
        (
            synth_input_ciphertext_vector,
            synth_output_ciphertext_vector,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (input_ciphertext_vector, mut output_ciphertext_vector) = context;
        unsafe {
            engine.discard_opp_lwe_ciphertext_vector_unchecked(
                &mut output_ciphertext_vector,
                &input_ciphertext_vector,
            )
        };
        (input_ciphertext_vector, output_ciphertext_vector)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (input_ciphertext_vector, output_ciphertext_vector) = context;
        let (proto_plaintext_vector, ..) = sample_proto;
        let proto_secret_key = repetition_proto;
        let raw_plaintext_vector =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector);
        let predicted_output = raw_plaintext_vector
            .iter()
            .map(|&a| a.wrapping_neg())
            .collect();
        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(output_ciphertext_vector);
        let proto_output_plaintext_vector = maker
            .decrypt_lwe_ciphertext_vector_to_plaintext_vector(
                proto_secret_key,
                &proto_output_ciphertext_vector,
            );
        maker.destroy_lwe_ciphertext_vector(input_ciphertext_vector);
        (
            predicted_output,
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (parameters.noise,)
    }

    fn verify(
        _parameters: &Self::Parameters,
        criteria: &Self::Criteria,
        outputs: &[Self::Outcome],
    ) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
