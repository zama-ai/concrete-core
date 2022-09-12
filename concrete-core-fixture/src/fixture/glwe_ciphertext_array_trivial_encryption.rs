use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesGlweCiphertextArray, PrototypesPlaintextArray};
use crate::generation::synthesizing::{SynthesizesGlweCiphertextArray, SynthesizesPlaintextArray};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    GlweCiphertextArrayEntity, GlweCiphertextArrayTrivialEncryptionEngine, GlweCiphertextCount,
    GlweDimension, PlaintextArrayEntity, PolynomialSize, Variance,
};

/// A fixture for the types implementing the `GlweCiphertextArrayTrivialEncryptionEngine` trait.
pub struct GlweCiphertextArrayTrivialEncryptionFixture;

#[derive(Debug)]
pub struct GlweCiphertextArrayTrivialEncryptionParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub count: GlweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, PlaintextArray, CiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (PlaintextArray, CiphertextArray)>
    for GlweCiphertextArrayTrivialEncryptionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextArrayTrivialEncryptionEngine<PlaintextArray, CiphertextArray>,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesGlweCiphertextArray<Precision, KeyDistribution, CiphertextArray>,
{
    type Parameters = GlweCiphertextArrayTrivialEncryptionParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (<Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,);
    type PreExecutionContext = (PlaintextArray,);
    type PostExecutionContext = (PlaintextArray, CiphertextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextArrayTrivialEncryptionParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(256),
                    count: GlweCiphertextCount(100),
                },
                GlweCiphertextArrayTrivialEncryptionParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(2),
                    count: GlweCiphertextCount(1),
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
        let raw_plaintext_array =
            Precision::Raw::uniform_vec(parameters.polynomial_size.0 * parameters.count.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        (proto_plaintext_array,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_plaintext_array,) = sample_proto;
        (maker.synthesize_plaintext_array(proto_plaintext_array),)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (plaintext_array,) = context;
        let ciphertext_array = unsafe {
            engine.trivially_encrypt_glwe_ciphertext_array_unchecked(
                parameters.glwe_dimension.to_glwe_size(),
                parameters.count,
                &plaintext_array,
            )
        };
        (plaintext_array, ciphertext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_array,) = sample_proto;
        let (plaintext_array, ciphertext_array) = context;
        let proto_output_ciphertext_array =
            maker.unsynthesize_glwe_ciphertext_array(ciphertext_array);
        let proto_output_plaintext_array = maker
            .trivially_decrypt_glwe_ciphertext_array_to_plaintext_array(
                &proto_output_ciphertext_array,
            );
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
