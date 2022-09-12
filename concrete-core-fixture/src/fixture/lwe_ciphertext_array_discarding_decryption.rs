use concrete_core::prelude::{
    LweCiphertextArrayDiscardingDecryptionEngine, LweCiphertextArrayEntity, LweCiphertextCount,
    LweDimension, LweSecretKeyEntity, PlaintextArrayEntity, Variance,
};

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

/// A fixture for the types implementing the `LweCiphertextArrayDiscardingDecryptionEngine` trait.
pub struct LweCiphertextArrayDiscardingDecryptionFixture;

#[derive(Debug)]
pub struct LweCiphertextArrayDiscardingDecryptionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

#[allow(clippy::type_complexity)]
impl<Precision, KeyDistribution, Engine, PlaintextArray, SecretKey, CiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, SecretKey, CiphertextArray)>
    for LweCiphertextArrayDiscardingDecryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine:
        LweCiphertextArrayDiscardingDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: LweSecretKeyEntity,
    CiphertextArray: LweCiphertextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweCiphertextArray<Precision, KeyDistribution, CiphertextArray>,
{
    type Parameters = LweCiphertextArrayDiscardingDecryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes =
        (
            <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
            <Maker as PrototypesLweCiphertextArray<
                Precision,
                KeyDistribution,
            >>::LweCiphertextArrayProto,
            <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        );
    type PreExecutionContext = (SecretKey, CiphertextArray, PlaintextArray);
    type PostExecutionContext = (SecretKey, CiphertextArray, PlaintextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextArrayDiscardingDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweCiphertextArrayDiscardingDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDiscardingDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDiscardingDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDiscardingDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDiscardingDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayDiscardingDecryptionParameters {
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
            maker.transform_raw_vec_to_plaintext_array(&raw_plaintext_array);
        let proto_ciphertext_array = maker.encrypt_plaintext_array_to_lwe_ciphertext_array(
            proto_secret_key,
            &proto_plaintext_array,
            parameters.noise,
        );
        let raw_output_plaintext_array =
            Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_output_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(&raw_output_plaintext_array);
        (
            proto_plaintext_array,
            proto_ciphertext_array,
            proto_output_plaintext_array,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        let (_, proto_ciphertext_array, proto_output_plaintext_array) = sample_proto;
        let synth_secret_key = maker.synthesize_lwe_secret_key(proto_secret_key);
        let synth_ciphertext_array = maker.synthesize_lwe_ciphertext_array(proto_ciphertext_array);
        let synth_output_plaintext_array =
            maker.synthesize_plaintext_array(proto_output_plaintext_array);
        (
            synth_secret_key,
            synth_ciphertext_array,
            synth_output_plaintext_array,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key, ciphertext_array, mut output_plaintext_array) = context;
        unsafe {
            engine.discard_decrypt_lwe_ciphertext_array_unchecked(
                &secret_key,
                &mut output_plaintext_array,
                &ciphertext_array,
            )
        };
        (secret_key, ciphertext_array, output_plaintext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array, ..) = sample_proto;
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
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
