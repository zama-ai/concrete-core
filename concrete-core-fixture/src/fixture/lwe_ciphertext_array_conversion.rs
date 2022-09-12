use concrete_core::prelude::{
    LweCiphertextArrayConversionEngine, LweCiphertextArrayEntity, LweCiphertextCount, LweDimension,
    Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextArray, PrototypesLweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::SynthesizesLweCiphertextArray;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `LweCiphertextArrayConversionEngine` trait.
pub struct LweCiphertextArrayConversionFixture;

#[derive(Debug)]
pub struct LweCiphertextArrayConversionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, InputCiphertextArray, OutputCiphertextArray>
    Fixture<Precision, (KeyDistribution,), Engine, (InputCiphertextArray, OutputCiphertextArray)>
    for LweCiphertextArrayConversionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextArrayConversionEngine<InputCiphertextArray, OutputCiphertextArray>,
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
    Maker: SynthesizesLweCiphertextArray<Precision, KeyDistribution, InputCiphertextArray>
        + SynthesizesLweCiphertextArray<Precision, KeyDistribution, OutputCiphertextArray>,
{
    type Parameters = LweCiphertextArrayConversionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesLweCiphertextArray<
            Precision,
            KeyDistribution,
        >>::LweCiphertextArrayProto,
    );
    type PreExecutionContext = (InputCiphertextArray,);
    type PostExecutionContext = (InputCiphertextArray, OutputCiphertextArray);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextArrayConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(6000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
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
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_ciphertext_array = maker.encrypt_plaintext_array_to_lwe_ciphertext_array(
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
        let (proto_ciphertext_array,) = sample_proto;
        (<Maker as SynthesizesLweCiphertextArray<
            Precision,
            KeyDistribution,
            InputCiphertextArray,
        >>::synthesize_lwe_ciphertext_array(
            maker,
            proto_ciphertext_array,
        ),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (input_ciphertext_array,) = context;
        let output_ciphertext_array =
            unsafe { engine.convert_lwe_ciphertext_array_unchecked(&input_ciphertext_array) };
        (input_ciphertext_array, output_ciphertext_array)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (key,) = repetition_proto;
        let (proto_ciphertext_array,) = sample_proto;
        let (input_ciphertext_array, output_ciphertext_array) = context;
        let proto_output_ciphertext_array =
            <Maker as SynthesizesLweCiphertextArray<
                Precision,
                KeyDistribution,
                OutputCiphertextArray,
            >>::unsynthesize_lwe_ciphertext_array(maker, output_ciphertext_array);
        let proto_plaintext_array =
            maker.decrypt_lwe_ciphertext_array_to_plaintext_array(key, proto_ciphertext_array);
        let proto_output_plaintext_array = <Maker as PrototypesLweCiphertextArray<
            Precision,
            KeyDistribution,
        >>::decrypt_lwe_ciphertext_array_to_plaintext_array(
            maker,
            key,
            &proto_output_ciphertext_array,
        );
        maker.destroy_lwe_ciphertext_array(input_ciphertext_array);
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
