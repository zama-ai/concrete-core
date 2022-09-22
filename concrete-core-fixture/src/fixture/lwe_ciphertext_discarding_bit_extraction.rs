use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweSecretKey, PrototypesLweBootstrapKey, PrototypesLweCiphertext,
    PrototypesLweCiphertextVector, PrototypesLweKeyswitchKey, PrototypesLweSecretKey,
    PrototypesPlaintext, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesLweBootstrapKey, SynthesizesLweCiphertext, SynthesizesLweCiphertextVector,
    SynthesizesLweKeyswitchKey,
};
use crate::generation::{
    BinaryKeyDistribution, GaussianKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker,
    TernaryKeyDistribution,
};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_delta_std_dev;
use concrete_core::commons::math::decomposition::SignedDecomposer;
use concrete_core::commons::numeric::{Numeric, UnsignedInteger};
use concrete_core::prelude::{
    BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, DeltaLog, DispersionParameter,
    ExtractedBitsCount, GaussianKeyKind, GlweDimension, LweBootstrapKeyEntity, LweCiphertextCount,
    LweCiphertextDiscardingBitExtractEngine, LweCiphertextEntity, LweCiphertextVectorEntity,
    LweDimension, LweKeyswitchKeyEntity, PolynomialSize, TernaryKeyKind, Variance,
};
use std::any::TypeId;

/// A fixture for the types implementing the `LweCiphertextDiscardingBitExtractEngine` trait.
pub struct LweCiphertextDiscardingBitExtractFixture;

#[derive(Debug)]
pub struct LweCiphertextDiscardingBitExtractParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub poly_size: PolynomialSize,
    pub decomp_level_count_bsk: DecompositionLevelCount,
    pub decomp_base_log_bsk: DecompositionBaseLog,
    pub decomp_level_count_ksk: DecompositionLevelCount,
    pub decomp_base_log_ksk: DecompositionBaseLog,
    pub extracted_bits_count: ExtractedBitsCount,
    pub delta_log: DeltaLog,
}

// To be able to use different sets of parameters between different precision for the fixtures this
// function needs to be const evaluable, the powf function to get the variance is not const, so we
// compute the value manually and paste the result as the variance to use
const fn get_parameters_for_raw_precision<T: IntegerPrecision>(
) -> [LweCiphertextDiscardingBitExtractParameters; 1_usize] {
    if T::Raw::BITS == 32 {
        [LweCiphertextDiscardingBitExtractParameters {
            // Offline evaluation 2.0f64.powf(-120.) is
            // 0.000000000000000000000000000000000000752316384526264f64
            noise: Variance(0.000000000000000000000000000000000000752316384526264f64),
            lwe_dimension: LweDimension(481),
            glwe_dimension: GlweDimension(1),
            poly_size: PolynomialSize(1024),
            decomp_level_count_bsk: DecompositionLevelCount(7),
            decomp_base_log_bsk: DecompositionBaseLog(4),
            decomp_level_count_ksk: DecompositionLevelCount(9),
            decomp_base_log_ksk: DecompositionBaseLog(1),
            extracted_bits_count: ExtractedBitsCount(5),
            delta_log: DeltaLog(27),
        }]
    } else if T::Raw::BITS == 64 {
        [LweCiphertextDiscardingBitExtractParameters {
            // Offline evaluation of 2.0f64.powf(-58.) is
            // 0.000000000000000000000000000000000000752316384526264f64
            noise: Variance(0.000000000000000000000000000000000000752316384526264f64),
            lwe_dimension: LweDimension(585),
            glwe_dimension: GlweDimension(1),
            poly_size: PolynomialSize(1024),
            decomp_level_count_bsk: DecompositionLevelCount(2),
            decomp_base_log_bsk: DecompositionBaseLog(10),
            decomp_level_count_ksk: DecompositionLevelCount(7),
            decomp_base_log_ksk: DecompositionBaseLog(4),
            extracted_bits_count: ExtractedBitsCount(5),
            delta_log: DeltaLog(59),
        }]
    } else {
        unreachable!()
    }
}

#[allow(clippy::type_complexity)]
impl<
        Precision,
        InputLweAndGlweKeyDistribution,
        OutputLweKeyDistribution,
        Engine,
        BootstrapKey,
        KeyswitchKey,
        InputCiphertext,
        OutputCiphertextVector,
    >
    Fixture<
        Precision,
        (InputLweAndGlweKeyDistribution, OutputLweKeyDistribution),
        Engine,
        (
            BootstrapKey,
            KeyswitchKey,
            InputCiphertext,
            OutputCiphertextVector,
        ),
    > for LweCiphertextDiscardingBitExtractFixture
where
    Precision: IntegerPrecision,
    InputLweAndGlweKeyDistribution: KeyDistributionMarker,
    OutputLweKeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextDiscardingBitExtractEngine<
        BootstrapKey,
        KeyswitchKey,
        InputCiphertext,
        OutputCiphertextVector,
    >,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    KeyswitchKey: LweKeyswitchKeyEntity,
    Maker: PrototypesGlweSecretKey<Precision, InputLweAndGlweKeyDistribution>
        + SynthesizesLweBootstrapKey<
            Precision,
            OutputLweKeyDistribution,
            InputLweAndGlweKeyDistribution,
            BootstrapKey,
        > + SynthesizesLweKeyswitchKey<
            Precision,
            InputLweAndGlweKeyDistribution,
            OutputLweKeyDistribution,
            KeyswitchKey,
        > + SynthesizesLweCiphertext<Precision, InputLweAndGlweKeyDistribution, InputCiphertext>
        + SynthesizesLweCiphertextVector<Precision, OutputLweKeyDistribution, OutputCiphertextVector>,
{
    type Parameters = LweCiphertextDiscardingBitExtractParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, InputLweAndGlweKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesLweSecretKey<Precision, OutputLweKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesLweBootstrapKey<
            Precision,
            OutputLweKeyDistribution,
            InputLweAndGlweKeyDistribution,
        >>::LweBootstrapKeyProto,
        <Maker as PrototypesLweKeyswitchKey<
            Precision,
            InputLweAndGlweKeyDistribution,
            OutputLweKeyDistribution,
        >>::LweKeyswitchKeyProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintext<Precision>>::PlaintextProto,
        <Maker as PrototypesLweCiphertext<Precision, InputLweAndGlweKeyDistribution>>::LweCiphertextProto,
        <Maker as PrototypesLweCiphertextVector<Precision,
            OutputLweKeyDistribution>>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (
        BootstrapKey,
        KeyswitchKey,
        OutputCiphertextVector,
        InputCiphertext,
    );
    type PostExecutionContext = (
        BootstrapKey,
        KeyswitchKey,
        OutputCiphertextVector,
        InputCiphertext,
    );
    type Criteria = (Vec<Variance>,);
    type Outcome = (ExtractedBitsCount, Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(get_parameters_for_raw_precision::<Precision>().into_iter())
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_output_lwe_secret_key = <Maker as PrototypesLweSecretKey<
            Precision,
            OutputLweKeyDistribution,
        >>::new_lwe_secret_key(
            maker, parameters.lwe_dimension
        );
        let proto_glwe_secret_key = <Maker as PrototypesGlweSecretKey<
            Precision,
            InputLweAndGlweKeyDistribution,
        >>::new_glwe_secret_key(
            maker, parameters.glwe_dimension, parameters.poly_size
        );

        let proto_input_lwe_secret_key = <Maker as PrototypesGlweSecretKey<
            Precision,
            InputLweAndGlweKeyDistribution,
        >>::transform_glwe_secret_key_to_lwe_secret_key(
            maker, &proto_glwe_secret_key
        );
        // maker.transform_glwe_secret_key_to_lwe_secret_key(&proto_glwe_secret_key);

        let proto_bootstrap_key = maker.new_lwe_bootstrap_key(
            &proto_output_lwe_secret_key,
            &proto_glwe_secret_key,
            parameters.decomp_level_count_bsk,
            parameters.decomp_base_log_bsk,
            parameters.noise,
        );
        let proto_keyswitch_key = maker.new_lwe_keyswitch_key(
            &proto_input_lwe_secret_key,
            &proto_output_lwe_secret_key,
            parameters.decomp_level_count_ksk,
            parameters.decomp_base_log_ksk,
            parameters.noise,
        );
        (
            proto_input_lwe_secret_key,
            proto_output_lwe_secret_key,
            proto_bootstrap_key,
            proto_keyswitch_key,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_input_lwe_secret_key, _, _, _) = repetition_proto;
        let raw_plaintext = Precision::Raw::uniform_between(
            1..1 << (Precision::Raw::BITS - parameters.delta_log.0),
        ) << parameters.delta_log.0;
        let proto_plaintext = maker.transform_raw_to_plaintext(&raw_plaintext);
        let proto_input_ciphertext = <Maker as PrototypesLweCiphertext<
            Precision,
            InputLweAndGlweKeyDistribution,
        >>::encrypt_plaintext_to_lwe_ciphertext(
            maker,
            proto_input_lwe_secret_key,
            &proto_plaintext,
            parameters.noise,
        );
        let proto_output_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputLweKeyDistribution,
        >>::trivially_encrypt_zeros_to_lwe_ciphertext_vector(
            maker,
            parameters.lwe_dimension,
            LweCiphertextCount(parameters.extracted_bits_count.0),
        );
        (
            proto_plaintext,
            proto_input_ciphertext,
            proto_output_ciphertext_vector,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, _, proto_bootstrap_key, proto_keyswitch_key) = repetition_proto;
        let (_, proto_input_ciphertext, proto_output_ciphertext_vector) = sample_proto;
        let synth_bootstrap_key = maker.synthesize_lwe_bootstrap_key(proto_bootstrap_key);
        let synth_keyswitch_key = maker.synthesize_lwe_keyswitch_key(proto_keyswitch_key);
        let synth_input_ciphertext = maker.synthesize_lwe_ciphertext(proto_input_ciphertext);
        let synth_output_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_output_ciphertext_vector);
        (
            synth_bootstrap_key,
            synth_keyswitch_key,
            synth_output_ciphertext_vector,
            synth_input_ciphertext,
        )
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (bootstrap_key, keyswitch_key, mut output_ciphertext_vector, input_ciphertext) =
            context;
        unsafe {
            engine.discard_extract_bits_lwe_ciphertext_unchecked(
                &mut output_ciphertext_vector,
                &input_ciphertext,
                &bootstrap_key,
                &keyswitch_key,
                parameters.extracted_bits_count,
                parameters.delta_log,
            )
        };
        (
            bootstrap_key,
            keyswitch_key,
            output_ciphertext_vector,
            input_ciphertext,
        )
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (bootstrap_key, keyswitch_key, output_ciphertext_vector, input_ciphertext) = context;
        let (_, proto_output_lwe_secret_key, _, _) = repetition_proto;
        let (proto_plaintext, ..) = sample_proto;
        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(output_ciphertext_vector);
        let proto_output_plaintext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            OutputLweKeyDistribution,
        >>::decrypt_lwe_ciphertext_vector_to_plaintext_vector(
            maker,
            proto_output_lwe_secret_key,
            &proto_output_ciphertext_vector,
        );
        maker.destroy_lwe_ciphertext(input_ciphertext);
        maker.destroy_lwe_bootstrap_key(bootstrap_key);
        maker.destroy_lwe_keyswitch_key(keyswitch_key);

        let extracted_bits_count = parameters.extracted_bits_count;
        let mut raw_plaintext_bits = Vec::<Precision::Raw>::with_capacity(extracted_bits_count.0);

        let mut decoded_plaintext =
            maker.transform_plaintext_to_raw(proto_plaintext) >> parameters.delta_log.0;

        for _ in 0..extracted_bits_count.0 {
            // Extract bits outputs the bit in the MSB
            raw_plaintext_bits
                .push((decoded_plaintext & Precision::Raw::one()) << (Precision::Raw::BITS - 1));
            decoded_plaintext >>= 1;
        }

        // Get bits from MSB to LSB
        raw_plaintext_bits.reverse();

        (
            extracted_bits_count,
            raw_plaintext_bits,
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let predicted_variance: Vec<Variance> = fix_estimate_bit_extraction_noise::<
            Precision::Raw,
            Variance,
            Variance,
            Variance,
            InputLweAndGlweKeyDistribution,
            OutputLweKeyDistribution,
        >(
            parameters.extracted_bits_count,
            (Precision::Raw::BITS - parameters.delta_log.0)
                .try_into()
                .unwrap(),
            LweDimension(parameters.glwe_dimension.0 * parameters.poly_size.0),
            parameters.lwe_dimension,
            parameters.glwe_dimension,
            parameters.poly_size,
            parameters.noise,
            parameters.noise,
            parameters.noise,
            parameters.decomp_base_log_ksk,
            parameters.decomp_level_count_ksk,
            parameters.decomp_base_log_ksk,
            parameters.decomp_level_count_ksk,
        );
        (predicted_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        assert!(!outputs.is_empty());
        let number_of_extracted_bits = outputs[0].0;

        assert!(outputs
            .iter()
            .all(|(extracted_bits, _, _)| *extracted_bits == number_of_extracted_bits));

        let (means, actual): (Vec<_>, Vec<_>) = outputs
            .iter()
            .cloned()
            .map(|(_, mean, actual)| (mean, actual))
            .unzip();

        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();

        let decomposer = SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(1));

        let recovered_extracted_bits: Vec<Precision::Raw> = actual
            .iter()
            .map(|&decrypted| {
                decomposer.closest_representable(decrypted) >> (Precision::Raw::BITS - 1)
            })
            .collect();
        let original_raw_bits: Vec<Precision::Raw> = means
            .iter()
            .map(|&raw_bit| raw_bit >> (Precision::Raw::BITS - 1))
            .collect();

        let extracted_bits_are_the_same = original_raw_bits == recovered_extracted_bits;

        let mut result_per_bit = vec![false; number_of_extracted_bits.0];

        for ((bit_idx, &var_for_bit), result_for_bit) in
            criteria.0.iter().enumerate().zip(result_per_bit.iter_mut())
        {
            let means_per_bit: Vec<Precision::Raw> = means
                .clone()
                .into_iter()
                .skip(bit_idx)
                .step_by(number_of_extracted_bits.0)
                .collect();
            let actual_per_bit: Vec<Precision::Raw> = actual
                .clone()
                .into_iter()
                .skip(bit_idx)
                .step_by(number_of_extracted_bits.0)
                .collect();

            assert!(means_per_bit.len() == actual_per_bit.len());

            *result_for_bit = assert_delta_std_dev(
                actual_per_bit.as_slice(),
                means_per_bit.as_slice(),
                var_for_bit,
            );
        }
        // Checks all results are true, returning the boolean itself
        extracted_bits_are_the_same && result_per_bit.iter().all(|&result_ok| result_ok)
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.
#[allow(clippy::too_many_arguments)]
pub fn fix_estimate_bit_extraction_noise<T, D1, D2, D3, K1, K2>(
    number_of_bits_to_extract: ExtractedBitsCount,
    total_precision: u32,
    input_lwe_mask_size: LweDimension,
    lwe_mask_size_after_ks: LweDimension,
    glwe_mask_size: GlweDimension,
    poly_size: PolynomialSize,
    dispersion_lwe: D1,
    dispersion_ksk: D2,
    dispersion_bsk: D3,
    base_log_ksk: DecompositionBaseLog,
    level_ksk: DecompositionLevelCount,
    base_log_bsk: DecompositionBaseLog,
    level_bsk: DecompositionLevelCount,
) -> Vec<Variance>
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K1: KeyDistributionMarker,
    K2: KeyDistributionMarker,
{
    let k1_type_id = TypeId::of::<K1>();
    let k2_type_id = TypeId::of::<K1>();
    if k1_type_id == TypeId::of::<BinaryKeyDistribution>()
        && k2_type_id == TypeId::of::<BinaryKeyDistribution>()
    {
        concrete_npe::estimate_bit_extraction_noise::<D1, D2, D3, BinaryKeyKind, BinaryKeyKind>(
            number_of_bits_to_extract,
            total_precision,
            input_lwe_mask_size,
            lwe_mask_size_after_ks,
            glwe_mask_size,
            poly_size,
            dispersion_lwe,
            dispersion_ksk,
            dispersion_bsk,
            base_log_ksk,
            level_ksk,
            base_log_bsk,
            level_bsk,
            T::BITS as u32,
        )
    } else if k1_type_id == TypeId::of::<TernaryKeyDistribution>()
        && k2_type_id == TypeId::of::<TernaryKeyDistribution>()
    {
        concrete_npe::estimate_bit_extraction_noise::<D1, D2, D3, TernaryKeyKind, TernaryKeyKind>(
            number_of_bits_to_extract,
            total_precision,
            input_lwe_mask_size,
            lwe_mask_size_after_ks,
            glwe_mask_size,
            poly_size,
            dispersion_lwe,
            dispersion_ksk,
            dispersion_bsk,
            base_log_ksk,
            level_ksk,
            base_log_bsk,
            level_bsk,
            T::BITS as u32,
        )
    } else if k1_type_id == TypeId::of::<GaussianKeyDistribution>()
        && k2_type_id == TypeId::of::<GaussianKeyDistribution>()
    {
        concrete_npe::estimate_bit_extraction_noise::<D1, D2, D3, GaussianKeyKind, GaussianKeyKind>(
            number_of_bits_to_extract,
            total_precision,
            input_lwe_mask_size,
            lwe_mask_size_after_ks,
            glwe_mask_size,
            poly_size,
            dispersion_lwe,
            dispersion_ksk,
            dispersion_bsk,
            base_log_ksk,
            level_ksk,
            base_log_bsk,
            level_bsk,
            T::BITS as u32,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
