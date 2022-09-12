use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesGlweCiphertext, PrototypesPlaintextArray};
use crate::generation::synthesizing::{SynthesizesGlweCiphertext, SynthesizesPlaintextArray};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    GlweCiphertextDiscardingTrivialEncryptionEngine, GlweCiphertextEntity, GlweDimension,
    PlaintextArrayEntity, PolynomialSize, Variance,
};

/// A fixture for the types implementing the `GlweCiphertextDiscardingTrivialEncryptionEngine`
/// trait.
pub struct GlweCiphertextDiscardingTrivialEncryptionFixture;

#[derive(Debug)]
pub struct GlweCiphertextDiscardingTrivialEncryptionParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, Ciphertext>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, Ciphertext)>
    for GlweCiphertextDiscardingTrivialEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextDiscardingTrivialEncryptionEngine<PlaintextArray, Ciphertext>,
    PlaintextArray: PlaintextArrayEntity,
    Ciphertext: GlweCiphertextEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesGlweCiphertext<Precision, KeyDistribution, Ciphertext>,
{
    type Parameters = GlweCiphertextDiscardingTrivialEncryptionParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesGlweCiphertext<Precision, KeyDistribution>>::GlweCiphertextProto,
    );
    type PreExecutionContext = (PlaintextArray, Ciphertext);
    type PostExecutionContext = (PlaintextArray, Ciphertext);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextDiscardingTrivialEncryptionParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                },
                GlweCiphertextDiscardingTrivialEncryptionParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(256),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let glwe_dimension = parameters.glwe_dimension;
        let polynomial_size = parameters.polynomial_size;
        let raw_plaintext_array = Precision::Raw::uniform_vec(polynomial_size.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let raw_glwe_container =
            Precision::Raw::uniform_vec(glwe_dimension.to_glwe_size().0 * polynomial_size.0);
        let proto_glwe_ciphertext = maker
            .transform_raw_vec_to_glwe_ciphertext(&raw_glwe_container, parameters.polynomial_size);
        (proto_plaintext_array, proto_glwe_ciphertext)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_plaintext_array, proto_glwe_ciphertext) = sample_proto;
        (
            maker.synthesize_plaintext_array(proto_plaintext_array),
            maker.synthesize_glwe_ciphertext(proto_glwe_ciphertext),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (plaintext_array, mut glwe_ciphertext) = context;
        unsafe {
            engine.discard_trivially_encrypt_glwe_ciphertext_unchecked(
                &mut glwe_ciphertext,
                &plaintext_array,
            )
        };
        (plaintext_array, glwe_ciphertext)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array, _) = sample_proto;
        let (plaintext_array, glwe_ciphertext) = context;
        let proto_output_ciphertext = maker.unsynthesize_glwe_ciphertext(glwe_ciphertext);
        let proto_output_plaintext_array =
            maker.trivially_decrypt_glwe_ciphertext(&proto_output_ciphertext);
        maker.destroy_plaintext_array(plaintext_array);
        (
            maker.transform_plaintext_array_to_raw_vec(proto_plaintext_array),
            maker.transform_plaintext_array_to_raw_vec(&proto_output_plaintext_array),
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (Variance(0.),)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
