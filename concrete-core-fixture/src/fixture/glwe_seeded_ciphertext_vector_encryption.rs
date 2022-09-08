use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextVector, PrototypesGlweSecretKey, PrototypesGlweSeededCiphertextVector,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesGlweSecretKey, SynthesizesGlweSeededCiphertextVector, SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    GlweCiphertextCount, GlweDimension, GlweSecretKeyEntity,
    GlweSeededCiphertextVectorEncryptionEngine, GlweSeededCiphertextVectorEntity,
    PlaintextVectorEntity, PolynomialSize, Variance,
};

/// A fixture for the types implementing the `GlweSeededCiphertextVectorEncryptionEngine` trait.
pub struct GlweSeededCiphertextVectorEncryptionFixture;

#[derive(Debug)]
pub struct GlweSeededCiphertextVectorEncryptionParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub count: GlweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, PlaintextVector, SecretKey, SeededCiphertextVector>
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (PlaintextVector, SecretKey, SeededCiphertextVector),
    > for GlweSeededCiphertextVectorEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweSeededCiphertextVectorEncryptionEngine<
        SecretKey,
        PlaintextVector,
        SeededCiphertextVector,
    >,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: GlweSecretKeyEntity,
    SeededCiphertextVector: GlweSeededCiphertextVectorEntity,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesGlweSeededCiphertextVector<Precision, KeyDistribution, SeededCiphertextVector>,
{
    type Parameters = GlweSeededCiphertextVectorEncryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes =
        (<Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,);
    type PreExecutionContext = (SecretKey, PlaintextVector);
    type PostExecutionContext = (SecretKey, PlaintextVector, SeededCiphertextVector);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweSeededCiphertextVectorEncryptionParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                    count: GlweCiphertextCount(10),
                    noise: Variance(0.00000001),
                },
                GlweSeededCiphertextVectorEncryptionParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(2),
                    count: GlweCiphertextCount(1),
                    noise: Variance(0.00000001),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        (proto_secret_key,)
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let raw_plaintext_vector =
            Precision::Raw::uniform_vec(parameters.polynomial_size.0 * parameters.count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        (proto_plaintext_vector,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        let (proto_plaintext_vector,) = sample_proto;
        (
            maker.synthesize_glwe_secret_key(proto_secret_key),
            maker.synthesize_plaintext_vector(proto_plaintext_vector),
        )
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key, plaintext_vector) = context;
        let seeded_ciphertext = unsafe {
            engine.encrypt_glwe_seeded_ciphertext_vector_unchecked(
                &secret_key,
                &plaintext_vector,
                parameters.noise,
            )
        };
        (secret_key, plaintext_vector, seeded_ciphertext)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_vector,) = sample_proto;
        let (proto_secret_key,) = repetition_proto;
        let (secret_key, plaintext_vector, seeded_ciphertext_vector) = context;
        let proto_output_seeded_ciphertext =
            maker.unsynthesize_glwe_seeded_ciphertext_vector(seeded_ciphertext_vector);
        let proto_output_ciphertext_vector = maker
            .transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
                &proto_output_seeded_ciphertext,
            );
        let proto_output_plaintext_vector = maker
            .decrypt_glwe_ciphertext_vector_to_plaintext_vector(
                proto_secret_key,
                &proto_output_ciphertext_vector,
            );
        maker.destroy_plaintext_vector(plaintext_vector);
        maker.destroy_glwe_secret_key(secret_key);
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

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
