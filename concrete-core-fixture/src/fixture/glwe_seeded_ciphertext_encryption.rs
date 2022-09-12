use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertext, PrototypesGlweSecretKey, PrototypesGlweSeededCiphertext,
    PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesGlweSecretKey, SynthesizesGlweSeededCiphertext, SynthesizesPlaintextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    GlweDimension, GlweSecretKeyEntity, GlweSeededCiphertextEncryptionEngine,
    GlweSeededCiphertextEntity, PlaintextArrayEntity, PolynomialSize, Variance,
};

/// A fixture for the types implementing the `GlweSeededCiphertextEncryptionEngine` trait.
pub struct GlweSeededCiphertextEncryptionFixture;

#[derive(Debug)]
pub struct GlweSeededCiphertextEncryptionParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, SecretKey, SeededCiphertext>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, SecretKey, SeededCiphertext)>
    for GlweSeededCiphertextEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweSeededCiphertextEncryptionEngine<SecretKey, PlaintextArray, SeededCiphertext>,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: GlweSecretKeyEntity,
    SeededCiphertext: GlweSeededCiphertextEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesGlweSeededCiphertext<Precision, KeyDistribution, SeededCiphertext>,
{
    type Parameters = GlweSeededCiphertextEncryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes = (<Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,);
    type PreExecutionContext = (SecretKey, PlaintextArray);
    type PostExecutionContext = (SecretKey, PlaintextArray, SeededCiphertext);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweSeededCiphertextEncryptionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                },
                GlweSeededCiphertextEncryptionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(2),
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
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.polynomial_size.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        (proto_plaintext_array,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        let (proto_plaintext_array,) = sample_proto;
        (
            maker.synthesize_glwe_secret_key(proto_secret_key),
            maker.synthesize_plaintext_array(proto_plaintext_array),
        )
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key, plaintext_array) = context;
        let seeded_ciphertext = unsafe {
            engine.encrypt_glwe_seeded_ciphertext_unchecked(
                &secret_key,
                &plaintext_array,
                parameters.noise,
            )
        };
        (secret_key, plaintext_array, seeded_ciphertext)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array,) = sample_proto;
        let (proto_secret_key,) = repetition_proto;
        let (secret_key, plaintext_array, seeded_ciphertext) = context;
        let proto_output_seeded_ciphertext =
            maker.unsynthesize_glwe_seeded_ciphertext(seeded_ciphertext);
        let proto_output_ciphertext = maker
            .transform_glwe_seeded_ciphertext_to_glwe_ciphertext(&proto_output_seeded_ciphertext);
        let proto_output_plaintext_array = maker
            .decrypt_glwe_ciphertext_to_plaintext_array(proto_secret_key, &proto_output_ciphertext);
        maker.destroy_plaintext_array(plaintext_array);
        maker.destroy_glwe_secret_key(secret_key);
        (
            maker.transform_plaintext_array_to_raw_vec(proto_plaintext_array),
            maker.transform_plaintext_array_to_raw_vec(&proto_output_plaintext_array),
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
