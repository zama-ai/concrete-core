use crate::fixture::lwe_ciphertext_discarding_bootstrap_1::fix_estimate_pbs_noise;
use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextArray, PrototypesGlweSecretKey, PrototypesLweBootstrapKey,
    PrototypesLweCiphertextArray, PrototypesLweSecretKey, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertextArray, SynthesizesLweBootstrapKey, SynthesizesLweCiphertextArray,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::statistical_test::assert_delta_std_dev;
use concrete_core::commons::numeric::Numeric;
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, DispersionParameter, GlweCiphertextArrayEntity,
    GlweCiphertextCount, GlweDimension, LogStandardDev, LweBootstrapKeyEntity,
    LweCiphertextArrayDiscardingBootstrapEngine, LweCiphertextArrayEntity, LweCiphertextCount,
    LweDimension, PolynomialSize, Variance,
};

/// A fixture for the types implementing the `LweCiphertextArrayDiscardingBootstrapEngine` trait.
pub struct LweCiphertextArrayDiscardingBootstrapFixture1;

#[derive(Debug)]
pub struct LweCiphertextArrayDiscardingBootstrapParameters1 {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub poly_size: PolynomialSize,
    pub decomp_level_count: DecompositionLevelCount,
    pub decomp_base_log: DecompositionBaseLog,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

#[allow(clippy::type_complexity)]
impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        BootstrapKey,
        AccumulatorArray,
        InputCiphertextArray,
        OutputCiphertextArray,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (
            BootstrapKey,
            AccumulatorArray,
            InputCiphertextArray,
            OutputCiphertextArray,
        ),
    > for LweCiphertextArrayDiscardingBootstrapFixture1
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextArrayDiscardingBootstrapEngine<
        BootstrapKey,
        AccumulatorArray,
        InputCiphertextArray,
        OutputCiphertextArray,
    >,
    InputCiphertextArray: LweCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
    AccumulatorArray: GlweCiphertextArrayEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    Maker: SynthesizesLweBootstrapKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            BootstrapKey,
        > + SynthesizesGlweCiphertextArray<Precision, OutputKeyDistribution, AccumulatorArray>
        + SynthesizesLweCiphertextArray<Precision, InputKeyDistribution, InputCiphertextArray>
        + SynthesizesLweCiphertextArray<Precision, OutputKeyDistribution, OutputCiphertextArray>,
{
    type Parameters = LweCiphertextArrayDiscardingBootstrapParameters1;
    type RepetitionPrototypes = (
        <Maker as PrototypesGlweCiphertextArray<Precision, OutputKeyDistribution>>::GlweCiphertextArrayProto,
        <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, OutputKeyDistribution>>::GlweSecretKeyProto,
        <Maker as PrototypesLweBootstrapKey<Precision, InputKeyDistribution, OutputKeyDistribution>>::LweBootstrapKeyProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesLweCiphertextArray<
            Precision,
            InputKeyDistribution,
        >>::LweCiphertextArrayProto,
        <Maker as PrototypesLweCiphertextArray<
            Precision,
            OutputKeyDistribution,
        >>::LweCiphertextArrayProto,
    );
    type PreExecutionContext = (
        BootstrapKey,
        AccumulatorArray,
        OutputCiphertextArray,
        InputCiphertextArray,
    );
    type PostExecutionContext = (
        BootstrapKey,
        AccumulatorArray,
        OutputCiphertextArray,
        InputCiphertextArray,
    );
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextArrayDiscardingBootstrapParameters1 {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    poly_size: PolynomialSize(512),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    lwe_ciphertext_count: LweCiphertextCount(10),
                },
                LweCiphertextArrayDiscardingBootstrapParameters1 {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    poly_size: PolynomialSize(1024),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    lwe_ciphertext_count: LweCiphertextCount(2),
                },
                LweCiphertextArrayDiscardingBootstrapParameters1 {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    poly_size: PolynomialSize(2048),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    lwe_ciphertext_count: LweCiphertextCount(1),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let raw_plaintext_array = vec![
            Precision::Raw::ONE << (Precision::Raw::BITS - 3);
            parameters.poly_size.0 * parameters.lwe_ciphertext_count.0
        ];
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_accumulator = maker.trivially_encrypt_plaintext_array_to_glwe_ciphertext_array(
            parameters.glwe_dimension.to_glwe_size(),
            GlweCiphertextCount(parameters.lwe_ciphertext_count.0),
            &proto_plaintext_array,
        );
        let proto_lwe_secret_key = <Maker as PrototypesLweSecretKey<
            Precision,
            InputKeyDistribution,
        >>::new_lwe_secret_key(maker, parameters.lwe_dimension);
        let proto_glwe_secret_key = <Maker as PrototypesGlweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::new_glwe_secret_key(
            maker, parameters.glwe_dimension, parameters.poly_size
        );
        let proto_bootstrap_key = maker.new_lwe_bootstrap_key(
            &proto_lwe_secret_key,
            &proto_glwe_secret_key,
            parameters.decomp_level_count,
            parameters.decomp_base_log,
            parameters.noise,
        );
        (
            proto_accumulator,
            proto_lwe_secret_key,
            proto_glwe_secret_key,
            proto_bootstrap_key,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (_, proto_lwe_secret_key, ..) = repetition_proto;
        let raw_plaintext_array = vec![
            Precision::Raw::ONE << (Precision::Raw::BITS - 2);
            parameters.lwe_ciphertext_count.0
        ];
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(&raw_plaintext_array);
        let proto_input_ciphertext_array = <Maker as PrototypesLweCiphertextArray<
            Precision,
            InputKeyDistribution,
        >>::encrypt_plaintext_array_to_lwe_ciphertext_array(
            maker,
            proto_lwe_secret_key,
            &proto_plaintext_array,
            parameters.noise,
        );
        let proto_output_ciphertext_array = <Maker as PrototypesLweCiphertextArray<
            Precision,
            OutputKeyDistribution,
        >>::trivially_encrypt_zeros_to_lwe_ciphertext_array(
            maker,
            LweDimension(parameters.glwe_dimension.0 * parameters.poly_size.0),
            parameters.lwe_ciphertext_count,
        );
        (
            proto_plaintext_array,
            proto_input_ciphertext_array,
            proto_output_ciphertext_array,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_accumulator, _, _, proto_bootstrap_key) = repetition_proto;
        let (_, proto_input_ciphertext_array, proto_output_ciphertext_array) = sample_proto;
        let synth_bootstrap_key = maker.synthesize_lwe_bootstrap_key(proto_bootstrap_key);
        let synth_accumulator_array = maker.synthesize_glwe_ciphertext_array(proto_accumulator);
        let synth_input_ciphertext_array =
            maker.synthesize_lwe_ciphertext_array(proto_input_ciphertext_array);
        let synth_output_ciphertext_array =
            maker.synthesize_lwe_ciphertext_array(proto_output_ciphertext_array);
        (
            synth_bootstrap_key,
            synth_accumulator_array,
            synth_output_ciphertext_array,
            synth_input_ciphertext_array,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (bootstrap_key, accumulator_array, mut output_ciphertext_array, input_ciphertext_array) =
            context;
        unsafe {
            engine.discard_bootstrap_lwe_ciphertext_array_unchecked(
                &mut output_ciphertext_array,
                &input_ciphertext_array,
                &accumulator_array,
                &bootstrap_key,
            )
        };
        (
            bootstrap_key,
            accumulator_array,
            output_ciphertext_array,
            input_ciphertext_array,
        )
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (bootstrap_key, accumulator_array, output_ciphertext_array, input_ciphertext_array) =
            context;
        let (_, _, proto_glwe_secret_key, _) = repetition_proto;
        let (proto_plaintext_array, ..) = sample_proto;
        let proto_output_ciphertext_array =
            maker.unsynthesize_lwe_ciphertext_array(output_ciphertext_array);
        let proto_output_lwe_secret_key =
            maker.transform_glwe_secret_key_to_lwe_secret_key(proto_glwe_secret_key);
        let proto_output_plaintext_array = <Maker as PrototypesLweCiphertextArray<
            Precision,
            OutputKeyDistribution,
        >>::decrypt_lwe_ciphertext_array_to_plaintext_array(
            maker,
            &proto_output_lwe_secret_key,
            &proto_output_ciphertext_array,
        );
        maker.destroy_lwe_ciphertext_array(input_ciphertext_array);
        maker.destroy_lwe_bootstrap_key(bootstrap_key);
        maker.destroy_glwe_ciphertext_array(accumulator_array);
        (
            maker.transform_plaintext_array_to_raw_vec(proto_plaintext_array),
            maker.transform_plaintext_array_to_raw_vec(&proto_output_plaintext_array),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let predicted_variance: Variance =
            fix_estimate_pbs_noise::<Precision::Raw, Variance, OutputKeyDistribution>(
                parameters.lwe_dimension,
                parameters.poly_size,
                parameters.glwe_dimension,
                parameters.decomp_base_log,
                parameters.decomp_level_count,
                parameters.noise,
            );
        (predicted_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_delta_std_dev(&actual, means.as_slice(), criteria.0)
    }
}
