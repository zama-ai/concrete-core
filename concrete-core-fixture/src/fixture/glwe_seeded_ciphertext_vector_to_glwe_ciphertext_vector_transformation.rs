use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextVector, PrototypesGlweSecretKey, PrototypesGlweSeededCiphertextVector,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertextVector, SynthesizesGlweSecretKey,
    SynthesizesGlweSeededCiphertextVector, SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use concrete_core::prelude::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, GlweSeededCiphertextVectorEntity,
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine, PlaintextVectorEntity,
};

/// A fixture for the types implementing the
/// `GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine` trait.
pub struct GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationFixture;

#[derive(Debug)]
pub struct GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub count: GlweCiphertextCount,
}

impl<
        Precision,
        Engine,
        PlaintextVector,
        SecretKey,
        InputCiphertextVector,
        OutputCiphertextVector,
    >
    Fixture<
        Precision,
        Engine,
        (
            PlaintextVector,
            SecretKey,
            InputCiphertextVector,
            OutputCiphertextVector,
        ),
    > for GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationFixture
where
    Precision: IntegerPrecision,
    Engine: GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine<
        InputCiphertextVector,
        OutputCiphertextVector,
    >,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: GlweSecretKeyEntity,
    InputCiphertextVector:
        GlweSeededCiphertextVectorEntity<KeyDistribution = SecretKey::KeyDistribution>,
    OutputCiphertextVector:
        GlweCiphertextVectorEntity<KeyDistribution = SecretKey::KeyDistribution>,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesGlweSecretKey<Precision, SecretKey>
        + SynthesizesGlweSeededCiphertextVector<Precision, InputCiphertextVector>
        + SynthesizesGlweCiphertextVector<Precision, OutputCiphertextVector>,
{
    type Parameters = GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesGlweSecretKey<Precision, SecretKey::KeyDistribution>>::GlweSecretKeyProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesGlweSeededCiphertextVector<
            Precision,
            InputCiphertextVector::KeyDistribution,
        >>::GlweSeededCiphertextVectorProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
    );
    type PreExecutionContext = (InputCiphertextVector,);
    type PostExecutionContext = (OutputCiphertextVector,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                    count: GlweCiphertextCount(10),
                    noise: Variance(0.00000001),
                },
                GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationParameters {
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
        let raw_plaintext_vector =
            Precision::Raw::uniform_vec(parameters.polynomial_size.0 * parameters.count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_seeded_ciphertext_vector = maker
            .encrypt_plaintext_vector_to_glwe_seeded_ciphertext_vector(
                &repetition_proto.0,
                &proto_plaintext_vector,
                parameters.noise,
            );
        (proto_seeded_ciphertext_vector, proto_plaintext_vector)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_seeded_ciphertext_vector, _) = sample_proto;
        let synth_seeded_ciphertext_vector =
            maker.synthesize_glwe_seeded_ciphertext_vector(proto_seeded_ciphertext_vector);
        (synth_seeded_ciphertext_vector,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_ciphertext_vector,) = context;
        let ciphertext_vector = unsafe {
            engine.transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector_unchecked(
                seeded_ciphertext_vector,
            )
        };
        (ciphertext_vector,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (ciphertext_vector,) = context;
        let (proto_secret_key,) = repetition_proto;
        let (_, proto_input_plaintext_vector) = sample_proto;
        let proto_output_ciphertext_vector =
            maker.unsynthesize_glwe_ciphertext_vector(ciphertext_vector);
        let proto_output_plaintext_vector = maker
            .decrypt_glwe_ciphertext_vector_to_plaintext_vector(
                proto_secret_key,
                &proto_output_ciphertext_vector,
            );
        (
            maker.transform_plaintext_vector_to_raw_vec(proto_input_plaintext_vector),
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
