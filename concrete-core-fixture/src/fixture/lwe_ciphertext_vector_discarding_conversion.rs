use concrete_core::prelude::{
    LweCiphertextCount, LweCiphertextVectorDiscardingConversionEngine, LweCiphertextVectorEntity,
    LweDimension, Variance,
};

use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::SynthesizesLweCiphertextVector;
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `LweCiphertextVectorDiscardingConversionEngine` trait.
pub struct LweCiphertextVectorDiscardingConversionFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorDiscardingConversionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<Precision, KeyDistribution, Engine, InputCiphertextVector, OutputCiphertextVector>
    Fixture<Precision, (KeyDistribution,), Engine, (InputCiphertextVector, OutputCiphertextVector)>
    for LweCiphertextVectorDiscardingConversionFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextVectorDiscardingConversionEngine<
        InputCiphertextVector,
        OutputCiphertextVector,
    >,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    Maker: SynthesizesLweCiphertextVector<Precision, KeyDistribution, InputCiphertextVector>
        + SynthesizesLweCiphertextVector<Precision, KeyDistribution, OutputCiphertextVector>,
{
    type Parameters = LweCiphertextVectorDiscardingConversionParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            KeyDistribution,
        >>::LweCiphertextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            KeyDistribution,
        >>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (InputCiphertextVector, OutputCiphertextVector);
    type PostExecutionContext = (InputCiphertextVector, OutputCiphertextVector);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorDiscardingConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweCiphertextVectorDiscardingConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDiscardingConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDiscardingConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDiscardingConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDiscardingConversionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDiscardingConversionParameters {
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
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_ciphertext_vector = maker.encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            key,
            &proto_plaintext_vector,
            parameters.noise,
        );
        let proto_output_ciphertext_vector = maker
            .trivially_encrypt_zeros_to_lwe_ciphertext_vector(
                parameters.lwe_dimension,
                parameters.lwe_ciphertext_count,
            );
        (proto_ciphertext_vector, proto_output_ciphertext_vector)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext_vector, proto_output_ciphertext_vector) = sample_proto;
        (
            <Maker as SynthesizesLweCiphertextVector<
                Precision,
                KeyDistribution,
                InputCiphertextVector,
            >>::synthesize_lwe_ciphertext_vector(maker, proto_ciphertext_vector),
            <Maker as SynthesizesLweCiphertextVector<
                Precision,
                KeyDistribution,
                OutputCiphertextVector,
            >>::synthesize_lwe_ciphertext_vector(maker, proto_output_ciphertext_vector),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (input_ciphertext_vector, mut output_ciphertext_vector) = context;
        unsafe {
            engine.discard_convert_lwe_ciphertext_vector_unchecked(
                &mut output_ciphertext_vector,
                &input_ciphertext_vector,
            )
        };
        (input_ciphertext_vector, output_ciphertext_vector)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (key,) = repetition_proto;
        let (proto_ciphertext_vector, _) = sample_proto;
        let (input_ciphertext_vector, output_ciphertext_vector) = context;
        let proto_output_ciphertext_vector =
            <Maker as SynthesizesLweCiphertextVector<
                Precision,
                KeyDistribution,
                OutputCiphertextVector,
            >>::unsynthesize_lwe_ciphertext_vector(maker, output_ciphertext_vector);
        let proto_plaintext_vector =
            maker.decrypt_lwe_ciphertext_vector_to_plaintext_vector(key, proto_ciphertext_vector);
        let proto_output_plaintext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            KeyDistribution,
        >>::decrypt_lwe_ciphertext_vector_to_plaintext_vector(
            maker,
            key,
            &proto_output_ciphertext_vector,
        );
        maker.destroy_lwe_ciphertext_vector(input_ciphertext_vector);
        (
            maker.transform_plaintext_vector_to_raw_vec(&proto_plaintext_vector),
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
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
