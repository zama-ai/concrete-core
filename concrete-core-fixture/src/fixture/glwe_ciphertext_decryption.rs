use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertext, PrototypesGlweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertext, SynthesizesGlweSecretKey, SynthesizesPlaintextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    GlweCiphertextDecryptionEngine, GlweCiphertextEntity, GlweDimension, GlweSecretKeyEntity,
    PlaintextArrayEntity, PolynomialSize, Variance,
};

/// A fixture for the types implementing the `GlweCiphertextDecryptionEngine` trait.
pub struct GlweCiphertextDecryptionFixture;

#[derive(Debug)]
pub struct GlweCiphertextDecryptionParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, SecretKey, Ciphertext>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, SecretKey, Ciphertext)>
    for GlweCiphertextDecryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextDecryptionEngine<SecretKey, Ciphertext, PlaintextArray>,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesGlweCiphertext<Precision, KeyDistribution, Ciphertext>,
{
    type Parameters = GlweCiphertextDecryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesGlweCiphertext<Precision, KeyDistribution>>::GlweCiphertextProto,
    );
    type PreExecutionContext = (SecretKey, Ciphertext);
    type PostExecutionContext = (SecretKey, Ciphertext, PlaintextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextDecryptionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                },
                GlweCiphertextDecryptionParameters {
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
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_secret_key,) = repetition_proto;
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.polynomial_size.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_ciphertext = maker.encrypt_plaintext_array_to_glwe_ciphertext(
            proto_secret_key,
            &proto_plaintext_array,
            parameters.noise,
        );
        (proto_plaintext_array, proto_ciphertext)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        let (_, proto_ciphertext_array) = sample_proto;
        let secret_key = maker.synthesize_glwe_secret_key(proto_secret_key);
        let ciphertext = maker.synthesize_glwe_ciphertext(proto_ciphertext_array);
        (secret_key, ciphertext)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key, ciphertext) = context;
        let plaintext_array =
            unsafe { engine.decrypt_glwe_ciphertext_unchecked(&secret_key, &ciphertext) };
        (secret_key, ciphertext, plaintext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array, _) = sample_proto;
        let (secret_key, ciphertext, plaintext_array) = context;
        let proto_output_plaintext_array = maker.unsynthesize_plaintext_array(plaintext_array);
        maker.destroy_glwe_ciphertext(ciphertext);
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
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
