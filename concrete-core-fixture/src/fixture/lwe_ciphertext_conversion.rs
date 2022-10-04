use concrete_core::prelude::{
    LweCiphertextConversionEngine, LweCiphertextEntity, LweDimension, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertext, PrototypesLweSecretKey, PrototypesPlaintext,
};
use crate::generation::synthesizing::SynthesizesLweCiphertext;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `LweCiphertextConversionEngine` trait.
pub struct LweCiphertextConversionFixture;

#[derive(Debug)]
pub struct LweCiphertextConversionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

impl<Precision, KeyDistribution, Engine, InputCiphertext, OutputCiphertext>
    Fixture<Precision, (KeyDistribution,), Engine, (InputCiphertext, OutputCiphertext)>
    for LweCiphertextConversionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextConversionEngine<InputCiphertext, OutputCiphertext>,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
    Maker: SynthesizesLweCiphertext<Precision, KeyDistribution, InputCiphertext>
        + SynthesizesLweCiphertext<Precision, KeyDistribution, OutputCiphertext>,
{
    type Parameters = LweCiphertextConversionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes =
        (<Maker as PrototypesLweCiphertext<Precision, KeyDistribution>>::LweCiphertextProto,);
    type PreExecutionContext = (InputCiphertext,);
    type PostExecutionContext = (InputCiphertext, OutputCiphertext);
    type Criteria = (Variance,);
    type Outcome = (Precision::Raw, Precision::Raw);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                },
                LweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                },
                LweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                },
                LweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                },
                LweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                },
                LweCiphertextConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                },
                LweCiphertextConversionParameters {
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
        let (key,) = repetition_proto;
        let raw_plaintext = Precision::Raw::uniform();
        let proto_plaintext = maker.transform_raw_to_plaintext(&raw_plaintext);
        let proto_ciphertext =
            maker.encrypt_plaintext_to_lwe_ciphertext(key, &proto_plaintext, parameters.noise);
        (proto_ciphertext,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext,) = sample_proto;
        (<Maker as SynthesizesLweCiphertext<
            Precision,
            KeyDistribution,
            InputCiphertext,
        >>::synthesize_lwe_ciphertext(
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
            unsafe { engine.convert_lwe_ciphertext_unchecked(&input_ciphertext) };
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
        let (output_ciphertext, input_ciphertext) = context;
        let proto_output_ciphertext = maker.unsynthesize_lwe_ciphertext(output_ciphertext);
        let proto_plaintext = maker.decrypt_lwe_ciphertext_to_plaintext(key, proto_ciphertext);
        let proto_output_plaintext = <Maker as PrototypesLweCiphertext<
            Precision,
            KeyDistribution,
        >>::decrypt_lwe_ciphertext_to_plaintext(
            maker, key, &proto_output_ciphertext
        );
        maker.destroy_lwe_ciphertext(input_ciphertext);
        (
            maker.transform_plaintext_to_raw(&proto_plaintext),
            maker.transform_plaintext_to_raw(&proto_output_plaintext),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (parameters.noise,)
    }

    fn verify(
        _parameters: &Self::Parameters,
        criteria: &Self::Criteria,
        outputs: &[Self::Outcome],
    ) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
