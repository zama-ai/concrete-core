use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertext, PrototypesGlweSecretKey, PrototypesGlweSeededCiphertext,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertext, SynthesizesGlweSecretKey, SynthesizesGlweSeededCiphertext,
    SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::{
    GlweCiphertextEntity, GlweSecretKeyEntity, GlweSeededCiphertextEntity,
    GlweSeededCiphertextToGlweCiphertextTransformationEngine, PlaintextVectorEntity,
};

/// A fixture for the types implementing the
/// `GlweSeededCiphertextToGlweCiphertextTransformationEngine` trait.
pub struct GlweSeededCiphertextToGlweCiphertextTransformationFixture;

#[derive(Debug)]
pub struct GlweSeededCiphertextToGlweCiphertextTransformationParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<
        Precision,
        KeyDistribution,
        Engine,
        PlaintextVector,
        SecretKey,
        InputCiphertext,
        OutputCiphertext,
    >
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (
            PlaintextVector,
            SecretKey,
            InputCiphertext,
            OutputCiphertext,
        ),
    > for GlweSeededCiphertextToGlweCiphertextTransformationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine:
        GlweSeededCiphertextToGlweCiphertextTransformationEngine<InputCiphertext, OutputCiphertext>,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: GlweSecretKeyEntity,
    InputCiphertext: GlweSeededCiphertextEntity,
    OutputCiphertext: GlweCiphertextEntity,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesGlweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesGlweSeededCiphertext<Precision, KeyDistribution, InputCiphertext>
        + SynthesizesGlweCiphertext<Precision, KeyDistribution, OutputCiphertext>,
{
    type Parameters = GlweSeededCiphertextToGlweCiphertextTransformationParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes =
        (
            <Maker as PrototypesGlweSeededCiphertext<
                Precision,
                KeyDistribution,
            >>::GlweSeededCiphertextProto,
            <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        );
    type PreExecutionContext = (InputCiphertext,);
    type PostExecutionContext = (OutputCiphertext,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweSeededCiphertextToGlweCiphertextTransformationParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                },
                GlweSeededCiphertextToGlweCiphertextTransformationParameters {
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
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.polynomial_size.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_seeded_ciphertext = maker.encrypt_plaintext_vector_to_glwe_seeded_ciphertext(
            &repetition_proto.0,
            &proto_plaintext_vector,
            parameters.noise,
        );
        (proto_seeded_ciphertext, proto_plaintext_vector)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_seeded_ciphertext, _) = sample_proto;
        let synth_seeded_ciphertext =
            maker.synthesize_glwe_seeded_ciphertext(proto_seeded_ciphertext);
        (synth_seeded_ciphertext,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_ciphertext,) = context;
        let ciphertext = unsafe {
            engine.transform_glwe_seeded_ciphertext_to_glwe_ciphertext_unchecked(seeded_ciphertext)
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
        let (_, proto_input_plaintext_vector) = sample_proto;
        let proto_output_ciphertext = maker.unsynthesize_glwe_ciphertext(ciphertext);
        let proto_output_plaintext_vector = maker.decrypt_glwe_ciphertext_to_plaintext_vector(
            proto_secret_key,
            &proto_output_ciphertext,
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
