use concrete_core::prelude::{
    LweCiphertextCount, LweCiphertextVectorDiscardingEncryptionEngine, LweCiphertextVectorEntity,
    LweDimension, LweSecretKeyEntity, PlaintextVectorEntity, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertextVector, SynthesizesLweSecretKey, SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `LweCiphertextVectorDiscardingEncryptionEngine` trait.
pub struct LweCiphertextVectorDiscardingEncryptionFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorDiscardingEncryptionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

#[allow(clippy::type_complexity)]
impl<Precision, KeyDistribution, Engine, PlaintextVector, SecretKey, CiphertextVector>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextVector, SecretKey, CiphertextVector)>
    for LweCiphertextVectorDiscardingEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine:
        LweCiphertextVectorDiscardingEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: LweSecretKeyEntity,
    CiphertextVector: LweCiphertextVectorEntity,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweCiphertextVector<Precision, KeyDistribution, CiphertextVector>,
{
    type Parameters = LweCiphertextVectorDiscardingEncryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes =
        (
            <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
            <Maker as PrototypesLweCiphertextVector<
                Precision,
                KeyDistribution,
            >>::LweCiphertextVectorProto,
        );
    type PreExecutionContext = (PlaintextVector, SecretKey, CiphertextVector);
    type PostExecutionContext = (PlaintextVector, SecretKey, CiphertextVector);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorDiscardingEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweCiphertextVectorDiscardingEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
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
        (proto_secret_key,)
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector);
        let proto_ciphertext_vector = maker.trivially_encrypt_zeros_to_lwe_ciphertext_vector(
            parameters.lwe_dimension,
            parameters.lwe_ciphertext_count,
        );
        (proto_plaintext_vector, proto_ciphertext_vector)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        let (proto_plaintext_vector, proto_ciphertext_vector) = sample_proto;
        let synth_plaintext_vector = maker.synthesize_plaintext_vector(proto_plaintext_vector);
        let synth_secret_key = maker.synthesize_lwe_secret_key(proto_secret_key);
        let synth_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_ciphertext_vector);
        (
            synth_plaintext_vector,
            synth_secret_key,
            synth_ciphertext_vector,
        )
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (plaintext_vector, secret_key, mut ciphertext_vector) = context;
        unsafe {
            engine.discard_encrypt_lwe_ciphertext_vector_unchecked(
                &secret_key,
                &mut ciphertext_vector,
                &plaintext_vector,
                parameters.noise,
            )
        };
        (plaintext_vector, secret_key, ciphertext_vector)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (plaintext_vector, secret_key, ciphertext_vector) = context;
        let (proto_secret_key,) = repetition_proto;
        let (proto_plaintext_vector, _) = sample_proto;
        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(ciphertext_vector);
        let proto_output_plaintext_vector = maker
            .decrypt_lwe_ciphertext_vector_to_plaintext_vector(
                proto_secret_key,
                &proto_output_ciphertext_vector,
            );
        maker.destroy_plaintext_vector(plaintext_vector);
        maker.destroy_lwe_secret_key(secret_key);
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
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
