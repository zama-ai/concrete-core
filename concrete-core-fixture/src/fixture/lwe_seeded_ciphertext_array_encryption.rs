use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextArray, PrototypesLweSecretKey, PrototypesLweSeededCiphertextArray,
    PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesLweSecretKey, SynthesizesLweSeededCiphertextArray, SynthesizesPlaintextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    LweCiphertextCount, LweDimension, LweSecretKeyEntity, LweSeededCiphertextArrayEncryptionEngine,
    LweSeededCiphertextArrayEntity, PlaintextArrayEntity, Variance,
};

/// A fixture for the types implementing the `LweSeededCiphertextEncryptionEngine` trait.
pub struct LweSeededCiphertextArrayEncryptionFixture;

#[derive(Debug)]
pub struct LweSeededCiphertextArrayEncryptionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, SecretKey, CiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, SecretKey, CiphertextArray)>
    for LweSeededCiphertextArrayEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweSeededCiphertextArrayEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: LweSecretKeyEntity,
    CiphertextArray: LweSeededCiphertextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweSeededCiphertextArray<Precision, KeyDistribution, CiphertextArray>,
{
    type Parameters = LweSeededCiphertextArrayEncryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (<Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,);
    type PreExecutionContext = (PlaintextArray, SecretKey);
    type PostExecutionContext = (PlaintextArray, SecretKey, CiphertextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayEncryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(6000),
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
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
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
        let (proto_plaintext,) = sample_proto;
        let synth_plaintext_array = maker.synthesize_plaintext_array(proto_plaintext);
        let synth_secret_key = maker.synthesize_lwe_secret_key(proto_secret_key);
        (synth_plaintext_array, synth_secret_key)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (plaintext_array, secret_key) = context;
        let seeded_ciphertext_array = unsafe {
            engine.encrypt_lwe_seeded_ciphertext_array_unchecked(
                &secret_key,
                &plaintext_array,
                parameters.noise,
            )
        };
        (plaintext_array, secret_key, seeded_ciphertext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (plaintext_array, secret_key, seeded_ciphertext_array) = context;
        let (proto_secret_key,) = repetition_proto;
        let (input_proto_plaintext_array,) = sample_proto;
        let proto_output_seeded_ciphertext_array =
            maker.unsynthesize_lwe_seeded_ciphertext_array(seeded_ciphertext_array);
        let proto_output_ciphertext = maker
            .transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
                &proto_output_seeded_ciphertext_array,
            );
        maker.destroy_plaintext_array(plaintext_array);
        maker.destroy_lwe_secret_key(secret_key);
        let output_proto_plaintext_array = maker.decrypt_lwe_ciphertext_array_to_plaintext_array(
            proto_secret_key,
            &proto_output_ciphertext,
        );
        (
            maker.transform_plaintext_array_to_raw_vec(input_proto_plaintext_array),
            maker.transform_plaintext_array_to_raw_vec(&output_proto_plaintext_array),
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
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
