use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextArray, PrototypesLweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertextArray, SynthesizesLweSecretKey, SynthesizesPlaintextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    LweCiphertextArrayDecryptionEngine, LweCiphertextArrayEntity, LweCiphertextCount, LweDimension,
    LweSecretKeyEntity, PlaintextArrayEntity, Variance,
};

/// A fixture for the types implementing the `LweCiphertextArrayDecryptionEngine` trait.
pub struct LweCiphertextArrayDecryptionFixture;

#[derive(Debug)]
pub struct LweCiphertextArrayDecryptionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, SecretKey, CiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, SecretKey, CiphertextArray)>
    for LweCiphertextArrayDecryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextArrayDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: LweSecretKeyEntity,
    CiphertextArray: LweCiphertextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweCiphertextArray<Precision, KeyDistribution, CiphertextArray>,
{
    type Parameters = LweCiphertextArrayDecryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesLweCiphertextArray<Precision, KeyDistribution>>::LweCiphertextArrayProto,
    );
    type PreExecutionContext = (SecretKey, CiphertextArray);
    type PostExecutionContext = (SecretKey, CiphertextArray, PlaintextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextArrayDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweCiphertextArrayDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDecryptionParameters {
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
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_secret_key,) = repetition_proto;
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_ciphertext_array = maker.encrypt_plaintext_array_to_lwe_ciphertext_array(
            proto_secret_key,
            &proto_plaintext_array,
            parameters.noise,
        );
        (proto_plaintext_array, proto_ciphertext_array)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        let (_, proto_ciphertext_array) = sample_proto;
        let secret_key = maker.synthesize_lwe_secret_key(proto_secret_key);
        let ciphertext_array = maker.synthesize_lwe_ciphertext_array(proto_ciphertext_array);
        (secret_key, ciphertext_array)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key, ciphertext_array) = context;
        let plaintext_array = unsafe {
            engine.decrypt_lwe_ciphertext_array_unchecked(&secret_key, &ciphertext_array)
        };
        (secret_key, ciphertext_array, plaintext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array, _) = sample_proto;
        let (secret_key, ciphertext_array, plaintext_array) = context;
        let proto_output_plaintext_array = maker.unsynthesize_plaintext_array(plaintext_array);
        maker.destroy_lwe_ciphertext_array(ciphertext_array);
        maker.destroy_lwe_secret_key(secret_key);
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
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
