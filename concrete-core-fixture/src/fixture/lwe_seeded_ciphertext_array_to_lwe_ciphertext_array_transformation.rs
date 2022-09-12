use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextArray, PrototypesLweSecretKey, PrototypesLweSeededCiphertextArray,
    PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertextArray, SynthesizesLweSecretKey, SynthesizesLweSeededCiphertextArray,
    SynthesizesPlaintextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::prelude::{
    LweCiphertextArrayEntity, LweCiphertextCount, LweDimension, LweSecretKeyEntity,
    LweSeededCiphertextArrayEntity,
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine, PlaintextArrayEntity,
    Variance,
};

/// A fixture for the types implementing the
/// `LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine` trait.
pub struct LweSeededCiphertextArrayToLweCiphertextArrayTransformationFixture;

#[derive(Debug)]
pub struct LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<
        Precision,
        Engine,
        KeyDistribution,
        PlaintextArray,
        SecretKey,
        InputCiphertextArray,
        OutputCiphertextArray,
    >
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (
            PlaintextArray,
            SecretKey,
            InputCiphertextArray,
            OutputCiphertextArray,
        ),
    > for LweSeededCiphertextArrayToLweCiphertextArrayTransformationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine<
        InputCiphertextArray,
        OutputCiphertextArray,
    >,
    PlaintextArray: PlaintextArrayEntity,
    SecretKey: LweSecretKeyEntity,
    InputCiphertextArray: LweSeededCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
    Maker: SynthesizesPlaintextArray<Precision, PlaintextArray>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLweSeededCiphertextArray<Precision, KeyDistribution, InputCiphertextArray>
        + SynthesizesLweCiphertextArray<Precision, KeyDistribution, OutputCiphertextArray>,
{
    type Parameters = LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters;
    type RepetitionPrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type SamplePrototypes = (
        <Maker as PrototypesLweSeededCiphertextArray<
            Precision,
            KeyDistribution,
        >>::LweSeededCiphertextArrayProto,
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
    );
    type PreExecutionContext = (InputCiphertextArray,);
    type PostExecutionContext = (OutputCiphertextArray,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweSeededCiphertextArrayToLweCiphertextArrayTransformationParameters {
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
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.lwe_ciphertext_count.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_seeded_ciphertext_array = maker
            .encrypt_plaintext_array_to_lwe_seeded_ciphertext_array(
                proto_secret_key,
                &proto_plaintext_array,
                parameters.noise,
            );
        (proto_seeded_ciphertext_array, proto_plaintext_array)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_seeded_ciphertext_array, _) = sample_proto;
        let synth_seeded_ciphertext_array =
            maker.synthesize_lwe_seeded_ciphertext_array(proto_seeded_ciphertext_array);
        (synth_seeded_ciphertext_array,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (seeded_ciphertext_array,) = context;
        let ciphertext_array = unsafe {
            engine.transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array_unchecked(
                seeded_ciphertext_array,
            )
        };
        (ciphertext_array,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (ciphertext_array,) = context;
        let (proto_secret_key,) = repetition_proto;
        let (_, input_proto_plaintext_array) = sample_proto;
        let output_proto_ciphertext_array =
            maker.unsynthesize_lwe_ciphertext_array(ciphertext_array);
        let output_proto_plaintext_array = maker.decrypt_lwe_ciphertext_array_to_plaintext_array(
            proto_secret_key,
            &output_proto_ciphertext_array,
        );
        (
            maker.transform_plaintext_array_to_raw_vec(input_proto_plaintext_array),
            maker.transform_plaintext_array_to_raw_vec(&output_proto_plaintext_array),
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
