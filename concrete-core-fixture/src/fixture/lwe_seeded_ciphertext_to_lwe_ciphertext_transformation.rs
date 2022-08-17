use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertext, PrototypesLweSecretKey, PrototypesLweSeededCiphertext,
    PrototypesPlaintext,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertext, SynthesizesLweSecretKey, SynthesizesLweSeededCiphertext,
    SynthesizesPlaintext,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::{
    LweCiphertextEntity, LweSecretKeyEntity, LweSeededCiphertextEntity,
    LweSeededCiphertextToLweCiphertextTransformationEngine, PlaintextEntity,
};

/// A fixture for the types implementing the
/// `LweSeededCiphertextToLweCiphertextTransformationEngine` trait.
pub struct LweSeededCiphertextToLweCiphertextTransformationFixture;

#[derive(Debug)]
pub struct LweSeededCiphertextToLweCiphertextTransformationParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

impl<
        Precision,
        KeyDistribution,
        Engine,
        Plaintext,
        SecretKey,
        InputCiphertext,
        OutputCiphertext,
    >
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (Plaintext, SecretKey, InputCiphertext, OutputCiphertext),
    > for LweSeededCiphertextToLweCiphertextTransformationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine:
        LweSeededCiphertextToLweCiphertextTransformationEngine<InputCiphertext, OutputCiphertext>,
    Plaintext: PlaintextEntity,
    SecretKey: LweSecretKeyEntity,
    InputCiphertext: LweSeededCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
    Maker: SynthesizesPlaintext<Precision, Plaintext>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweSeededCiphertext<Precision, KeyDistribution, InputCiphertext>
        + SynthesizesLweCiphertext<Precision, KeyDistribution, OutputCiphertext>,
{
    type Parameters = LweSeededCiphertextToLweCiphertextTransformationParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesLweSeededCiphertext<Precision, KeyDistribution>>::LweSeededCiphertextProto,
        Precision::Raw);
    type PreExecutionContext = (InputCiphertext,);
    type PostExecutionContext = (OutputCiphertext,);
    type Criteria = (Variance,);
    type Outcome = (Precision::Raw, Precision::Raw);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededCiphertextToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                },
                LweSeededCiphertextToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                },
                LweSeededCiphertextToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                },
                LweSeededCiphertextToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                },
                LweSeededCiphertextToLweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                },
                LweSeededCiphertextToLweCiphertextTransformationParameters {
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
