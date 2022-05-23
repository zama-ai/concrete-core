use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertext, PrototypesLweSecretKey, PrototypesLweSeededCiphertext,
    PrototypesPlaintext,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertext, SynthesizesLweSecretKey, SynthesizesLweSeededCiphertext,
    SynthesizesPlaintext,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::{
    LweCiphertextEntity, LweSecretKeyEntity, LweSeededCiphertextEntity,
    LweSeededToLweCiphertextTransformationEngine, PlaintextEntity,
};

/// A fixture for the types implementing the `LweSeededToLweCiphertextTransformationEngine` trait.
pub struct LweSeededToLweCiphertextTransformationFixture;

#[derive(Debug)]
pub struct LweSeededToLweCiphertextTransformationParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

impl<Precision, Engine, Plaintext, SecretKey, InputCiphertext, OutputCiphertext>
    Fixture<Precision, Engine, (Plaintext, SecretKey, InputCiphertext, OutputCiphertext)>
    for LweSeededToLweCiphertextTransformationFixture
where
    Precision: IntegerPrecision,
    Engine: LweSeededToLweCiphertextTransformationEngine<InputCiphertext, OutputCiphertext>,
    Plaintext: PlaintextEntity,
    SecretKey: LweSecretKeyEntity,
    InputCiphertext: LweSeededCiphertextEntity<KeyDistribution = SecretKey::KeyDistribution>,
    OutputCiphertext: LweCiphertextEntity<KeyDistribution = SecretKey::KeyDistribution>,
    Maker: SynthesizesPlaintext<Precision, Plaintext>
        + SynthesizesLweSecretKey<Precision, SecretKey>
        + SynthesizesLweSeededCiphertext<Precision, InputCiphertext>
        + SynthesizesLweCiphertext<Precision, OutputCiphertext>,
{
    type Parameters = LweSeededToLweCiphertextTransformationParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, SecretKey::KeyDistribution>>::LweSecretKeyProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesLweSeededCiphertext<Precision, InputCiphertext::KeyDistribution>>::LweSeededCiphertextProto,
        Precision::Raw);
    type PreExecutionContext = (InputCiphertext,);
    type PostExecutionContext = (OutputCiphertext,);
    type Criteria = (Variance,);
    type Outcome = (Precision::Raw, Precision::Raw);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                },
                LweSeededToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                },
                LweSeededToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                },
                LweSeededToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                },
                LweSeededToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                },
                LweSeededToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(6000),
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
        let raw_plaintext = Precision::Raw::uniform();
        let proto_plaintext = maker.transform_raw_to_plaintext(&raw_plaintext);
        let proto_seeded_ciphertext = maker.encrypt_plaintext_to_lwe_seeded_ciphertext(
            proto_secret_key,
            &proto_plaintext,
            parameters.noise,
        );
        (proto_seeded_ciphertext, raw_plaintext)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_seeded_ciphertext, _) = sample_proto;
        let synth_seeded_ciphertext =
            maker.synthesize_lwe_seeded_ciphertext(proto_seeded_ciphertext);
        (synth_seeded_ciphertext,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_ciphertext,) = context;
        let ciphertext = unsafe {
            engine.transform_lwe_seeded_ciphertext_to_lwe_ciphertext_unchecked(seeded_ciphertext)
        };
        (ciphertext,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (ciphertext,) = context;
        let (proto_secret_key,) = repetition_proto;
        let (_, raw_plaintext) = sample_proto;
        let proto_output_ciphertext = maker.unsynthesize_lwe_ciphertext(ciphertext);
        let proto_plaintext =
            maker.decrypt_lwe_ciphertext_to_plaintext(proto_secret_key, &proto_output_ciphertext);
        (
            *raw_plaintext,
            maker.transform_plaintext_to_raw(&proto_plaintext),
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
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
