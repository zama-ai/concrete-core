use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextVector, PrototypesGlweSecretKey, PrototypesLweBootstrapKey,
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesPlaintextVector,
    TransmutesGlweToLweSecretKeyPrototype,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertextVector, SynthesizesLweBootstrapKey, SynthesizesLweCiphertextVector,
};
use crate::generation::{IntegerPrecision, Maker};
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::numeric::{CastInto, Numeric};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    GlweCiphertextCount, GlweCiphertextVectorEntity, LweBootstrapKeyEntity, LweCiphertextCount,
    LweCiphertextVectorDiscardingBootstrapEngine, LweCiphertextVectorEntity,
};

/// A fixture for the types implementing the `LweCiphertextVectorDiscardingBootstrapEngine` trait.
pub struct LweCiphertextVectorDiscardingBootstrapFixture2;

#[derive(Debug)]
pub struct LweCiphertextVectorDiscardingBootstrapParameters2 {
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
        Engine,
        BootstrapKey,
        AccumulatorVector,
        InputCiphertextVector,
        OutputCiphertextVector,
    >
    Fixture<
        Precision,
        Engine,
        (
            BootstrapKey,
            AccumulatorVector,
            InputCiphertextVector,
            OutputCiphertextVector,
        ),
    > for LweCiphertextVectorDiscardingBootstrapFixture2
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextVectorDiscardingBootstrapEngine<
        BootstrapKey,
        AccumulatorVector,
        InputCiphertextVector,
        OutputCiphertextVector,
    >,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    AccumulatorVector:
        GlweCiphertextVectorEntity<KeyDistribution = OutputCiphertextVector::KeyDistribution>,
    BootstrapKey: LweBootstrapKeyEntity<
        InputKeyDistribution = InputCiphertextVector::KeyDistribution,
        OutputKeyDistribution = OutputCiphertextVector::KeyDistribution,
    >,
    Maker: TransmutesGlweToLweSecretKeyPrototype<Precision, OutputCiphertextVector::KeyDistribution>
        + SynthesizesLweBootstrapKey<Precision, BootstrapKey>
        + SynthesizesGlweCiphertextVector<Precision, AccumulatorVector>
        + SynthesizesLweCiphertextVector<Precision, InputCiphertextVector>
        + SynthesizesLweCiphertextVector<Precision, OutputCiphertextVector>,
{
    type Parameters = LweCiphertextVectorDiscardingBootstrapParameters2;
    type RepetitionPrototypes = (
        <Maker as PrototypesGlweCiphertextVector<Precision, OutputCiphertextVector::KeyDistribution>>::GlweCiphertextVectorProto,
        <Maker as PrototypesLweSecretKey<Precision, InputCiphertextVector::KeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, OutputCiphertextVector::KeyDistribution>>::GlweSecretKeyProto,
        <Maker as PrototypesLweBootstrapKey<Precision, InputCiphertextVector::KeyDistribution, OutputCiphertextVector::KeyDistribution>>::LweBootstrapKeyProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            InputCiphertextVector::KeyDistribution,
        >>::LweCiphertextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputCiphertextVector::KeyDistribution,
        >>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (
        BootstrapKey,
        AccumulatorVector,
        InputCiphertextVector,
        OutputCiphertextVector,
    );
    type PostExecutionContext = (
        BootstrapKey,
        AccumulatorVector,
        InputCiphertextVector,
        OutputCiphertextVector,
    );
    type Criteria = (i64,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorDiscardingBootstrapParameters2 {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    poly_size: PolynomialSize(512),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    lwe_ciphertext_count: LweCiphertextCount(10),
                },
                LweCiphertextVectorDiscardingBootstrapParameters2 {
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                    lwe_dimension: LweDimension(630),
                    glwe_dimension: GlweDimension(1),
                    poly_size: PolynomialSize(1024),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    lwe_ciphertext_count: LweCiphertextCount(2),
                },
                LweCiphertextVectorDiscardingBootstrapParameters2 {
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
        let log_degree = f64::log2(parameters.poly_size.0 as f64) as i32;
        let slots = parameters.poly_size.0 * parameters.lwe_ciphertext_count.0;
        let raw_plaintext_vector: Vec<Precision::Raw> = (0..slots)
            .map(|i| {
                ((i % parameters.poly_size.0) as f64
                    * 2_f64.powi(Precision::Raw::BITS as i32 - log_degree - 1))
                .cast_into()
            })
            .collect();
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_accumulator = maker.trivially_encrypt_plaintext_vector_to_glwe_ciphertext_vector(
            parameters.glwe_dimension.to_glwe_size(),
            GlweCiphertextCount(parameters.lwe_ciphertext_count.0),
            &proto_plaintext_vector,
        );
        let proto_lwe_secret_key = <Maker as PrototypesLweSecretKey<
            Precision,
            InputCiphertextVector::KeyDistribution,
        >>::new_lwe_secret_key(maker, parameters.lwe_dimension);
        let proto_glwe_secret_key = <Maker as PrototypesGlweSecretKey<
            Precision,
            OutputCiphertextVector::KeyDistribution,
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
        let log_degree = f64::log2(parameters.poly_size.0 as f64) as i32;
        let raw_plaintext_vector: Vec<Precision::Raw> = (0..parameters.lwe_ciphertext_count.0)
            .map(|_| {
                ((parameters.poly_size.0 as f64
                    - (10. * f64::sqrt((parameters.lwe_dimension.0 as f64) / 16.0)))
                    * 2_f64.powi(Precision::Raw::BITS as i32 - log_degree - 1))
                .cast_into()
            })
            .collect();
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector);
        let proto_input_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            InputCiphertextVector::KeyDistribution,
        >>::encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            maker,
            proto_lwe_secret_key,
            &proto_plaintext_vector,
            parameters.noise,
        );
        let proto_output_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputCiphertextVector::KeyDistribution,
        >>::trivially_encrypt_zeros_to_lwe_ciphertext_vector(
            maker,
            LweDimension(parameters.glwe_dimension.0 * parameters.poly_size.0),
            parameters.lwe_ciphertext_count,
        );
        (
            proto_plaintext_vector,
            proto_input_ciphertext_vector,
            proto_output_ciphertext_vector,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_accumulator, _, _, proto_bootstrap_key) = repetition_proto;
        let (_, proto_input_ciphertext_vector, proto_output_ciphertext_vector) = sample_proto;
        let synth_bootstrap_key = maker.synthesize_lwe_bootstrap_key(proto_bootstrap_key);
        let synth_accumulator_vector = maker.synthesize_glwe_ciphertext_vector(proto_accumulator);
        let synth_input_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_input_ciphertext_vector);
        let synth_output_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_output_ciphertext_vector);
        (
            synth_bootstrap_key,
            synth_accumulator_vector,
            synth_input_ciphertext_vector,
            synth_output_ciphertext_vector,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (
            bootstrap_key,
            accumulator_vector,
            input_ciphertext_vector,
            mut output_ciphertext_vector,
        ) = context;
        unsafe {
            engine.discard_bootstrap_lwe_ciphertext_vector_unchecked(
                &mut output_ciphertext_vector,
                &input_ciphertext_vector,
                &accumulator_vector,
                &bootstrap_key,
            )
        };
        (
            bootstrap_key,
            accumulator_vector,
            input_ciphertext_vector,
            output_ciphertext_vector,
        )
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (bootstrap_key, accumulator_vector, input_ciphertext_vector, output_ciphertext_vector) =
            context;
        let (_, _, proto_glwe_secret_key, _) = repetition_proto;
        let (proto_plaintext_vector, ..) = sample_proto;
        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(output_ciphertext_vector);
        let proto_output_lwe_secret_key =
            maker.transmute_glwe_secret_key_to_lwe_secret_key(proto_glwe_secret_key);
        let proto_output_plaintext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputCiphertextVector::KeyDistribution,
        >>::decrypt_lwe_ciphertext_vector_to_plaintext_vector(
            maker,
            &proto_output_lwe_secret_key,
            &proto_output_ciphertext_vector,
        );
        maker.destroy_lwe_ciphertext_vector(input_ciphertext_vector);
        maker.destroy_lwe_bootstrap_key(bootstrap_key);
        maker.destroy_glwe_ciphertext_vector(accumulator_vector);
        (
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector),
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let log_degree = f64::log2(parameters.poly_size.0 as f64) as i32;
        let delta_max: i64 = ((5. * f64::sqrt((parameters.lwe_dimension.0 as f64) / 16.0))
            * 2_f64.powi(Precision::Raw::BITS as i32 - log_degree - 1))
            as i64;
        (delta_max,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (delta_max,) = criteria;
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();

        for (x, y) in means.into_iter().zip(actual.into_iter()) {
            for (expected, obtained) in x.into_iter().zip(y) {
                if (<Precision::Raw as CastInto<i64>>::cast_into(expected)
                    - <Precision::Raw as CastInto<i64>>::cast_into(obtained))
                .abs()
                    > *delta_max
                {
                    return false;
                }
            }
        }
        true
    }
}
