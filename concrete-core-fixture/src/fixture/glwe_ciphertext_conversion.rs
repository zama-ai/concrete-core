use concrete_core::prelude::{
    GlweCiphertextConversionEngine, GlweCiphertextEntity, GlweDimension, PolynomialSize, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertext, PrototypesGlweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::SynthesizesGlweCiphertext;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `GlweCiphertextConversionEngine` trait.
pub struct GlweCiphertextConversionFixture;

#[derive(Debug)]
pub struct GlweCiphertextConversionParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, KeyDistribution, Engine, InputCiphertext, OutputCiphertext>
    Fixture<Precision, (KeyDistribution,), Engine, (InputCiphertext, OutputCiphertext)>
    for GlweCiphertextConversionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextConversionEngine<InputCiphertext, OutputCiphertext>,
    InputCiphertext: GlweCiphertextEntity,
    OutputCiphertext: GlweCiphertextEntity,
    Maker: SynthesizesGlweCiphertext<Precision, KeyDistribution, InputCiphertext>
        + SynthesizesGlweCiphertext<Precision, KeyDistribution, OutputCiphertext>,
{
    type Parameters = GlweCiphertextConversionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,);
    type SamplePrototypes =
        (<Maker as PrototypesGlweCiphertext<Precision, KeyDistribution>>::GlweCiphertextProto,);
    type PreExecutionContext = (InputCiphertext,);
    type PostExecutionContext = (InputCiphertext, OutputCiphertext);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(512),
                },
                GlweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(1024),
                },
                GlweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(2048),
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
        let (key,) = repetition_proto;

        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.polynomial_size.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_ciphertext_array = maker.encrypt_plaintext_array_to_glwe_ciphertext(
            key,
            &proto_plaintext_array,
            parameters.noise,
        );
        (proto_ciphertext_array,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext,) = sample_proto;
        (<Maker as SynthesizesGlweCiphertext<
            Precision,
            KeyDistribution,
            InputCiphertext,
        >>::synthesize_glwe_ciphertext(
            maker, proto_ciphertext
        ),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (input_ciphertext,) = context;
        let output_ciphertext =
            unsafe { engine.convert_glwe_ciphertext_unchecked(&input_ciphertext) };
        (input_ciphertext, output_ciphertext)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (key,) = repetition_proto;
        let (proto_ciphertext,) = sample_proto;
        let (input_ciphertext, output_ciphertext) = context;
        let proto_output_ciphertext = <Maker as SynthesizesGlweCiphertext<
            Precision,
            KeyDistribution,
            OutputCiphertext,
        >>::unsynthesize_glwe_ciphertext(
            maker, output_ciphertext
        );

        let proto_plaintext_array =
            maker.decrypt_glwe_ciphertext_to_plaintext_array(key, proto_ciphertext);
        let proto_output_plaintext_array = <Maker as PrototypesGlweCiphertext<
            Precision,
            KeyDistribution,
        >>::decrypt_glwe_ciphertext_to_plaintext_array(
            maker, key, &proto_output_ciphertext
        );
        maker.destroy_glwe_ciphertext(input_ciphertext);
        (
            maker.transform_plaintext_array_to_raw_vec(&proto_plaintext_array),
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
