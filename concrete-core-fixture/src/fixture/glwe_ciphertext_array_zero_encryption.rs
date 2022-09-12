use concrete_core::prelude::{
    GlweCiphertextArrayEntity, GlweCiphertextArrayZeroEncryptionEngine, GlweCiphertextCount,
    GlweDimension, GlweSecretKeyEntity, PolynomialSize, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextArray, PrototypesGlweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{SynthesizesGlweCiphertextArray, SynthesizesGlweSecretKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `GlweCiphertextArrayZeroEncryptionEngine` trait.
pub struct GlweCiphertextArrayZeroEncryptionFixture;

#[derive(Debug)]
pub struct GlweCiphertextArrayZeroEncryptionParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub count: GlweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, SecretKey, CiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (SecretKey, CiphertextArray)>
    for GlweCiphertextArrayZeroEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextArrayZeroEncryptionEngine<SecretKey, CiphertextArray>,
    SecretKey: GlweSecretKeyEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
    Maker: SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesGlweCiphertextArray<Precision, KeyDistribution, CiphertextArray>,
{
    type Parameters = GlweCiphertextArrayZeroEncryptionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes = ();
    type PreExecutionContext = (SecretKey,);
    type PostExecutionContext = (SecretKey, CiphertextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextArrayZeroEncryptionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                    count: GlweCiphertextCount(100),
                },
                GlweCiphertextArrayZeroEncryptionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(2),
                    count: GlweCiphertextCount(1),
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
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = repetition_proto;
        (maker.synthesize_glwe_secret_key(proto_secret_key),)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key,) = context;
        let ciphertext_array = unsafe {
            engine.zero_encrypt_glwe_ciphertext_array_unchecked(
                &secret_key,
                parameters.noise,
                parameters.count,
            )
        };
        (secret_key, ciphertext_array)
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_secret_key,) = repetition_proto;
        let (secret_key, ciphertext_array) = context;
        let proto_output_ciphertext_array =
            maker.unsynthesize_glwe_ciphertext_array(ciphertext_array);
        let proto_output_plaintext_array = maker.decrypt_glwe_ciphertext_array_to_plaintext_array(
            proto_secret_key,
            &proto_output_ciphertext_array,
        );
        maker.destroy_glwe_secret_key(secret_key);
        (
            Precision::Raw::zero_vec(parameters.polynomial_size.0 * parameters.count.0),
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
