use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesLweSeededCiphertextVector,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertextVector, SynthesizesLweSecretKey, SynthesizesLweSeededCiphertextVector,
    SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    LweCiphertextCount, LweCiphertextVectorEntity, LweDimension, LweSecretKeyEntity,
    LweSeededCiphertextVectorEntity,
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine, PlaintextVectorEntity,
    Variance,
};

/// A fixture for the types implementing the
/// `LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine` trait.
pub struct LweSeededCiphertextVectorToLweCiphertextVectorTransformationFixture;

#[derive(Debug)]
pub struct LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<
        Precision,
        Engine,
        KeyDistribution,
        PlaintextVector,
        SecretKey,
        InputCiphertextVector,
        OutputCiphertextVector,
    >
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (
            PlaintextVector,
            SecretKey,
            InputCiphertextVector,
            OutputCiphertextVector,
        ),
    > for LweSeededCiphertextVectorToLweCiphertextVectorTransformationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine<
        InputCiphertextVector,
        OutputCiphertextVector,
    >,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: LweSecretKeyEntity,
    InputCiphertextVector: LweSeededCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweSeededCiphertextVector<Precision, KeyDistribution, InputCiphertextVector>
        + SynthesizesLweCiphertextVector<Precision, KeyDistribution, OutputCiphertextVector>,
{
    type Parameters = LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesLweSeededCiphertextVector<
            Precision,
            KeyDistribution,
        >>::LweSeededCiphertextVectorProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
    );
    type PreExecutionContext = (InputCiphertextVector,);
    type PostExecutionContext = (OutputCiphertextVector,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextVectorToLweCiphertextVectorTransformationParameters {
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
        let (proto_secret_key,) = repetition_proto;
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_seeded_ciphertext_vector = maker
            .encrypt_plaintext_vector_to_lwe_seeded_ciphertext_vector(
                proto_secret_key,
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
            maker.synthesize_lwe_seeded_ciphertext_vector(proto_seeded_ciphertext_vector);
        (synth_seeded_ciphertext_vector,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_ciphertext_vector,) = context;
        let ciphertext_vector = unsafe {
            engine.transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_unchecked(
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
        let (_, input_proto_plaintext_vector) = sample_proto;
        let output_proto_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(ciphertext_vector);
        let output_proto_plaintext_vector = maker
            .decrypt_lwe_ciphertext_vector_to_plaintext_vector(
                proto_secret_key,
                &output_proto_ciphertext_vector,
            );
        (
            maker.transform_plaintext_vector_to_raw_vec(input_proto_plaintext_vector),
            maker.transform_plaintext_vector_to_raw_vec(&output_proto_plaintext_vector),
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
