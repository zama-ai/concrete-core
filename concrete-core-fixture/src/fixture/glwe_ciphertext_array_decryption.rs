use concrete_core::prelude::{
    GlweCiphertextArrayDecryptionEngine, GlweCiphertextArrayEntity, GlweCiphertextCount,
    GlweDimension, GlweSecretKeyEntity, PlaintextArrayEntity, PolynomialSize, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextArray, PrototypesGlweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertextArray, SynthesizesGlweSecretKey, SynthesizesPlaintextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `GlweCiphertextArrayDecryptionEngine` trait.
pub struct GlweCiphertextArrayDecryptionFixture;

#[derive(Debug)]
pub struct GlweCiphertextArrayDecryptionParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub count: GlweCiphertextCount,
    pub noise: Variance,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, SecretKey, CiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, SecretKey, CiphertextArray)>
    for GlweCiphertextArrayDecryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextArrayDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: GlweSecretKeyEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesGlweCiphertextArray<Precision, KeyDistribution, CiphertextArray>,
{
    type Parameters = GlweCiphertextArrayDecryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesGlweCiphertextArray<Precision,
            KeyDistribution>>::GlweCiphertextArrayProto,
    );
    type PreExecutionContext = (SecretKey, CiphertextArray);
    type PostExecutionContext = (SecretKey, PlaintextArray, CiphertextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextArrayDecryptionParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                    count: GlweCiphertextCount(10),
                    noise: Variance(0.00000001),
                },
                GlweCiphertextArrayDecryptionParameters {
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
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_secret_key,) = repetition_proto;
        let raw_plaintext_array =
            Precision::Raw::uniform_vec(parameters.polynomial_size.0 * parameters.count.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_ciphertext_array = maker.encrypt_plaintext_array_to_glwe_ciphertext_array(
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
        (
            maker.synthesize_glwe_secret_key(proto_secret_key),
            maker.synthesize_glwe_ciphertext_array(proto_ciphertext_array),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key, ciphertext_array) = context;
        let plaintext_array = unsafe {
            engine.decrypt_glwe_ciphertext_array_unchecked(&secret_key, &ciphertext_array)
        };
        (secret_key, plaintext_array, ciphertext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array, _) = sample_proto;
        let (proto_secret_key,) = repetition_proto;
        let (secret_key, plaintext_array, ciphertext_array) = context;
        let proto_output_ciphertext_array =
            maker.unsynthesize_glwe_ciphertext_array(ciphertext_array);
        let proto_output_plaintext_array = maker.decrypt_glwe_ciphertext_array_to_plaintext_array(
            proto_secret_key,
            &proto_output_ciphertext_array,
        );
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
