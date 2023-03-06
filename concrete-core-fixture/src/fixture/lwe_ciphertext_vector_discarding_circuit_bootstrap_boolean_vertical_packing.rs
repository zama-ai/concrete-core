use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweSecretKey, PrototypesLweBootstrapKey, PrototypesLweCiphertextVector,
    PrototypesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys, PrototypesLweSecretKey,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesLweBootstrapKey, SynthesizesLweCiphertextVector,
    SynthesizesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
    SynthesizesPlaintextVector,
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
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine,
    LweCiphertextVectorEntity, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    LweDimension, PlaintextVectorEntity, PolynomialSize, TernaryKeyKind, Variance,
};
use std::any::TypeId;

/// A fixture for the types implementing the
/// `LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine` trait.
pub struct LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingFixture;

#[derive(Debug, Clone)]
pub struct LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingParameters<
    Precision: IntegerPrecision,
> {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub decomp_level_count_bsk: DecompositionLevelCount,
    pub decomp_base_log_bsk: DecompositionBaseLog,
    pub decomp_level_count_pfpksk: DecompositionLevelCount,
    pub decomp_base_log_pfpksk: DecompositionBaseLog,
    pub decomp_level_count_cbs: DecompositionLevelCount,
    pub decomp_base_log_cbs: DecompositionBaseLog,
    pub extracted_bits_count: ExtractedBitsCount,
    pub delta_log: DeltaLog,
    // Here we take the parameters by values (so we'll clone them) as deriving Debug was not
    // working automatically and required some manual implementations which seemed to be more
    // trouble than it was worth
    // TODO: if you feel like it, improve this to be able to take a reference while
    // deriving/implementing Debug in a straightforward way
    pub gen_raw_vec_lut_fn: fn(Self) -> Vec<Precision::Raw>,
}

// Trivial identity lut, where the big lut contains a single polynomial that has all the information
// required to perform a vertical packing only triggering a blind rotate
fn generate_raw_vec_identity_trivial_lut<Precision: IntegerPrecision>(
    parameters: LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingParameters<
        Precision,
    >,
) -> Vec<Precision::Raw> {
    let mut lut_vec = Vec::with_capacity(1 << parameters.extracted_bits_count.0);

    // The Raw from Precision::Raw does not have the std::iter::Step trait available which would
    // allow to use a range + collect approach (and std::iter::Step is unstable at the moment),
    // so we'll do a dumb loop instead
    let mut curr_value = Precision::Raw::zero();
    let max_value = Precision::Raw::one() << parameters.extracted_bits_count.0;

    while curr_value < max_value {
        lut_vec.push(curr_value << parameters.delta_log.0);
        curr_value += Precision::Raw::one();
    }

    lut_vec
}

// To be able to use different sets of parameters between different precision for the fixtures this
// function needs to be const evaluable, the powf function to get the variance is not const, so we
// compute the value manually and paste the result as the variance to use
const fn get_parameters_for_raw_precision<Precision: IntegerPrecision>(
) -> [LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingParameters<Precision>;
       1_usize] {
    if Precision::Raw::BITS == 32 {
        [
            LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingParameters {
                // Offline evaluation 2.0f64.powf(-120.) is
                // 0.000000000000000000000000000000000000752316384526264
                noise: Variance(0.001000000000000000000000000000000001752316384526264f64),
                lwe_dimension: LweDimension(10),
                glwe_dimension: GlweDimension(1),
                polynomial_size: PolynomialSize(512),
                decomp_level_count_bsk: DecompositionLevelCount(7),
                decomp_base_log_bsk: DecompositionBaseLog(4),
                decomp_level_count_pfpksk: DecompositionLevelCount(7),
                decomp_base_log_pfpksk: DecompositionBaseLog(4),
                decomp_level_count_cbs: DecompositionLevelCount(7),
                decomp_base_log_cbs: DecompositionBaseLog(4),
                extracted_bits_count: ExtractedBitsCount(9),
                delta_log: DeltaLog(23),
                gen_raw_vec_lut_fn: generate_raw_vec_identity_trivial_lut::<Precision>,
            },
        ]
    } else if Precision::Raw::BITS == 64 {
        [
            LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingParameters {
                // Offline evaluation 2.0f64.powf(-120.) is
                // 0.000000000000000000000000000000000000752316384526264
                noise: Variance(0.000000000000000000000000000000000000752316384526264f64),
                lwe_dimension: LweDimension(10),
                glwe_dimension: GlweDimension(1),
                polynomial_size: PolynomialSize(512),
                decomp_level_count_bsk: DecompositionLevelCount(9),
                decomp_base_log_bsk: DecompositionBaseLog(4),
                decomp_level_count_pfpksk: DecompositionLevelCount(9),
                decomp_base_log_pfpksk: DecompositionBaseLog(4),
                decomp_level_count_cbs: DecompositionLevelCount(4),
                decomp_base_log_cbs: DecompositionBaseLog(6),
                extracted_bits_count: ExtractedBitsCount(9),
                delta_log: DeltaLog(53),
                gen_raw_vec_lut_fn: generate_raw_vec_identity_trivial_lut::<Precision>,
            },
        ]
    } else {
        unreachable!()
    }
}

#[allow(clippy::type_complexity)]
impl<
        Precision,
        BigLweAndGlweKeyDistribution,
        SmallLweKeyDistribution,
        Engine,
        BootstrapKey,
        CBSPFPKSK,
        LUTs,
        InputCiphertextVector,
        OutputCiphertextVector,
    >
    Fixture<
        Precision,
        (BigLweAndGlweKeyDistribution, SmallLweKeyDistribution),
        Engine,
        (
            BootstrapKey,
            CBSPFPKSK,
            LUTs,
            InputCiphertextVector,
            OutputCiphertextVector,
        ),
    > for LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingFixture
where
    Precision: IntegerPrecision + 'static + Clone,
    BigLweAndGlweKeyDistribution: KeyDistributionMarker,
    SmallLweKeyDistribution: KeyDistributionMarker,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    CBSPFPKSK: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    LUTs: PlaintextVectorEntity,
    Engine: LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine<
        InputCiphertextVector,
        OutputCiphertextVector,
        BootstrapKey,
        LUTs,
        CBSPFPKSK,
    >,
    Maker: PrototypesGlweSecretKey<Precision, BigLweAndGlweKeyDistribution>
        + SynthesizesLweBootstrapKey<
            Precision,
            SmallLweKeyDistribution,
            BigLweAndGlweKeyDistribution,
            BootstrapKey,
        > + SynthesizesLweCiphertextVector<Precision, SmallLweKeyDistribution, InputCiphertextVector>
        + SynthesizesLweCiphertextVector<
            Precision,
            BigLweAndGlweKeyDistribution,
            OutputCiphertextVector,
        > + SynthesizesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
            Precision,
            BigLweAndGlweKeyDistribution,
            BigLweAndGlweKeyDistribution,
            CBSPFPKSK,
        > + SynthesizesPlaintextVector<Precision, LUTs>,
{
    type Parameters =
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingParameters<Precision>;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweSecretKey<
            Precision,
            BigLweAndGlweKeyDistribution
        >>::LweSecretKeyProto,
        <Maker as PrototypesLweSecretKey<Precision, SmallLweKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesLweBootstrapKey<
            Precision,
            SmallLweKeyDistribution,
            BigLweAndGlweKeyDistribution,
        >>::LweBootstrapKeyProto,
        <Maker as PrototypesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
            Precision,
            BigLweAndGlweKeyDistribution,
            BigLweAndGlweKeyDistribution,
        >>::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision, SmallLweKeyDistribution
        >>::LweCiphertextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision, BigLweAndGlweKeyDistribution
        >>::LweCiphertextVectorProto,
    );
    type PreExecutionContext = (
        OutputCiphertextVector,
        InputCiphertextVector,
        BootstrapKey,
        LUTs,
        CBSPFPKSK,
    );
    type PostExecutionContext = (
        OutputCiphertextVector,
        InputCiphertextVector,
        BootstrapKey,
        LUTs,
        CBSPFPKSK,
    );
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(get_parameters_for_raw_precision::<Precision>().into_iter())
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_small_lwe_sk = <Maker as PrototypesLweSecretKey<
            Precision,
            SmallLweKeyDistribution,
        >>::new_lwe_secret_key(maker, parameters.lwe_dimension);
        let proto_glwe_sk = <Maker as PrototypesGlweSecretKey<
            Precision,
            BigLweAndGlweKeyDistribution,
        >>::new_glwe_secret_key(
            maker, parameters.glwe_dimension, parameters.polynomial_size
        );
        let proto_big_lwe_sk = <Maker as PrototypesGlweSecretKey<
            Precision,
            BigLweAndGlweKeyDistribution,
        >>::transform_glwe_secret_key_to_lwe_secret_key(
            maker, &proto_glwe_sk
        );

        let proto_bootstrap_key = <Maker as PrototypesLweBootstrapKey<
            Precision,
            SmallLweKeyDistribution,
            BigLweAndGlweKeyDistribution,
        >>::new_lwe_bootstrap_key(
            maker,
            &proto_small_lwe_sk,
            &proto_glwe_sk,
            parameters.decomp_level_count_bsk,
            parameters.decomp_base_log_bsk,
            parameters.noise,
        );

        let proto_cbs_pfpksk =
            <Maker as PrototypesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
                Precision,
                BigLweAndGlweKeyDistribution,
                BigLweAndGlweKeyDistribution,
            >>::new_lwe_private_functional_packing_keyswitch_key(
                maker,
                &proto_big_lwe_sk,
                &proto_glwe_sk,
                parameters.decomp_base_log_pfpksk,
                parameters.decomp_level_count_pfpksk,
                parameters.noise,
            );

        let parameters_clone: Self::Parameters = parameters.clone();
        let raw_plaintext_vector: Vec<_> = (parameters.gen_raw_vec_lut_fn)(parameters_clone);

        let proto_lut_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector);

        (
            proto_big_lwe_sk,
            proto_small_lwe_sk,
            proto_bootstrap_key,
            proto_cbs_pfpksk,
            proto_lut_plaintext_vector,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let number_of_bits = parameters.extracted_bits_count.0;

        let mut input_cleartext = Precision::Raw::uniform_between(0..1 << number_of_bits);

        let mut encoded_input_bits_vec = vec![Precision::Raw::zero(); number_of_bits];

        for bit in encoded_input_bits_vec.iter_mut().rev() {
            *bit = (input_cleartext & Precision::Raw::one()) << (Precision::Raw::BITS - 1);
            input_cleartext >>= 1;
        }

        let proto_encoded_input_bits_vec =
            maker.transform_raw_vec_to_plaintext_vector(&encoded_input_bits_vec);

        let (_, proto_small_lwe_sk, _, _, proto_lut_plaintext_vector) = repetition_proto;

        let proto_input_lwe_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            SmallLweKeyDistribution,
        >>::encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            maker,
            proto_small_lwe_sk,
            &proto_encoded_input_bits_vec,
            parameters.noise,
        );

        let big_lwe_dim = LweDimension(parameters.glwe_dimension.0 * parameters.polynomial_size.0);

        let number_of_output_ciphertexts = LweCiphertextCount(
            maker
                .transform_plaintext_vector_to_raw_vec(proto_lut_plaintext_vector)
                .len()
                / (1 << number_of_bits),
        );

        let proto_output_lwe_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            BigLweAndGlweKeyDistribution,
        >>::trivially_encrypt_zeros_to_lwe_ciphertext_vector(
            maker,
            big_lwe_dim,
            number_of_output_ciphertexts,
        );

        (
            proto_encoded_input_bits_vec,
            proto_input_lwe_ciphertext_vector,
            proto_output_lwe_ciphertext_vector,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, _, proto_bootstrap_key, proto_cbs_pfpksk, proto_lut_plaintext_vector) =
            repetition_proto;

        let (_, proto_input_lwe_ciphertext_vector, proto_output_lwe_ciphertext_vector) =
            sample_proto;

        let synth_output_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_output_lwe_ciphertext_vector);

        let synth_input_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_input_lwe_ciphertext_vector);

        let synth_bootstrap_key = maker.synthesize_lwe_bootstrap_key(proto_bootstrap_key);

        let synth_luts = maker.synthesize_plaintext_vector(proto_lut_plaintext_vector);

        let synth_cbs_pfpksk = maker
            .synthesize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
                proto_cbs_pfpksk,
            );

        (
            synth_output_ciphertext_vector,
            synth_input_ciphertext_vector,
            synth_bootstrap_key,
            synth_luts,
            synth_cbs_pfpksk,
        )
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (
            mut output_ciphertext_vector,
            input_ciphertext_vector,
            bootstrap_key,
            luts,
            cbs_pfpksk,
        ) = context;

        unsafe {
            engine
                .discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
                    &mut output_ciphertext_vector,
                    &input_ciphertext_vector,
                    &bootstrap_key,
                    &luts,
                    parameters.decomp_level_count_cbs,
                    parameters.decomp_base_log_cbs,
                    &cbs_pfpksk,
                )
        };

        (
            output_ciphertext_vector,
            input_ciphertext_vector,
            bootstrap_key,
            luts,
            cbs_pfpksk,
        )
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_big_lwe_sk, _, _, _, _) = repetition_proto;

        let (output_ciphertext_vector, input_ciphertext_vector, bootstrap_key, luts, cbs_pfpksk) =
            context;

        let (proto_encoded_input_bits_vec, _, _) = sample_proto;

        let number_of_output_cts = output_ciphertext_vector.lwe_ciphertext_count();

        let proto_luts = maker.unsynthesize_plaintext_vector(luts);
        let raw_luts = maker.transform_plaintext_vector_to_raw_vec(&proto_luts);

        let small_lut_size = raw_luts.len() / number_of_output_cts.0;
        let number_of_polynomials_in_small_lut = small_lut_size / parameters.polynomial_size.0;

        let number_of_bits_to_select_small_lut: usize =
            (usize::BITS - 1 - number_of_polynomials_in_small_lut.leading_zeros()) as usize;

        let encoded_raw_input_bits =
            maker.transform_plaintext_vector_to_raw_vec(proto_encoded_input_bits_vec);

        let selected_small_lut_idx: usize = if number_of_bits_to_select_small_lut > 0 {
            // Construct index using the necessary MSBs (extracted_bits = n_msb +
            // log2(polynomial_size))
            let mut index: usize = 0;
            for &bit in encoded_raw_input_bits[0..number_of_bits_to_select_small_lut].iter() {
                index <<= 1;
                // Complicated to write conversion for a Precsision::Raw value to usize, dumb
                // workaround to still be able to write what we need
                let decoded_bit = (bit >> (Precision::Raw::BITS - 1)) & Precision::Raw::one();
                if decoded_bit == Precision::Raw::one() {
                    index |= 1;
                }
            }
            index
        } else {
            0
        };

        // Use the remaining bits to select the value we are expecting as an output
        let mut value_index_in_small_lut: usize = 0;
        for &bit in encoded_raw_input_bits[number_of_bits_to_select_small_lut..].iter() {
            value_index_in_small_lut <<= 1;
            // Complicated to write conversion for a Precsision::Raw value to usize, dumb
            // workaround to still be able to write what we need
            let decoded_bit = (bit >> (Precision::Raw::BITS - 1)) & Precision::Raw::one();

            if decoded_bit == Precision::Raw::one() {
                value_index_in_small_lut |= 1;
            }
        }

        let proto_output_ciphertext_vector =
            maker.unsynthesize_lwe_ciphertext_vector(output_ciphertext_vector);

        let proto_decrypted_output_plaintext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            BigLweAndGlweKeyDistribution,
        >>::decrypt_lwe_ciphertext_vector_to_plaintext_vector(
            maker,
            proto_big_lwe_sk,
            &proto_output_ciphertext_vector,
        );

        let raw_decrypted_output_plaintext_vector =
            maker.transform_plaintext_vector_to_raw_vec(&proto_decrypted_output_plaintext_vector);

        let mut vec_expected = vec![];
        let mut vec_actual = vec![];

        for (small_lut_idx, &decrypted_plaintext) in
            raw_decrypted_output_plaintext_vector.iter().enumerate()
        {
            let lut_val = raw_luts[small_lut_idx * small_lut_size
                + selected_small_lut_idx * parameters.polynomial_size.0
                + value_index_in_small_lut];

            vec_expected.push(lut_val);
            vec_actual.push(decrypted_plaintext);
        }

        maker.destroy_lwe_ciphertext_vector(input_ciphertext_vector);
        maker.destroy_lwe_bootstrap_key(bootstrap_key);
        maker.destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(cbs_pfpksk);

        (vec_expected, vec_actual)
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (fix_estimate_wop_pbs_noise::<
            Precision::Raw,
            Variance,
            Variance,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
        >(
            parameters.extracted_bits_count,
            parameters.lwe_dimension,
            parameters.polynomial_size,
            parameters.glwe_dimension,
            parameters.decomp_base_log_cbs,
            parameters.decomp_level_count_cbs,
            parameters.noise,
            parameters.noise,
            Precision::Raw::BITS as u32,
        ),)
    }

    fn verify(
        parameters: &Self::Parameters,
        criteria: &Self::Criteria,
        outputs: &[Self::Outcome],
    ) -> bool {
        let (expected, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();

        let expected: Vec<Precision::Raw> = expected.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(Precision::Raw::BITS - parameters.delta_log.0),
            DecompositionLevelCount(1),
        );

        let recovered_lut_evals: Vec<Precision::Raw> = actual
            .iter()
            .map(|&decrypted| decomposer.closest_representable(decrypted))
            .collect();

        let recovered_lut_evals_are_correct = expected == recovered_lut_evals;

        let noise_ok = assert_delta_std_dev(&expected, &actual, criteria.0);

        recovered_lut_evals_are_correct && noise_ok
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.
#[allow(clippy::too_many_arguments)]
pub fn fix_estimate_wop_pbs_noise<T, D1, D2, K1, K2>(
    number_of_bits_to_extract: ExtractedBitsCount,
    lwe_mask_size_after_bit_extraction: LweDimension,
    poly_size: PolynomialSize,
    glwe_mask_size: GlweDimension,
    base_log_cb: DecompositionBaseLog,
    level_cb: DecompositionLevelCount,
    dispersion_cb_bsk: D1,
    dispersion_cb_pfksk: D2,
    log2_modulus: u32,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K1: KeyDistributionMarker,
    K2: KeyDistributionMarker,
{
    let k1_type_id = TypeId::of::<K1>();
    let k2_type_id = TypeId::of::<K1>();
    if k1_type_id == TypeId::of::<BinaryKeyDistribution>()
        && k2_type_id == TypeId::of::<BinaryKeyDistribution>()
    {
        concrete_npe::estimate_wop_pbs_noise::<D1, D2, BinaryKeyKind, BinaryKeyKind>(
            number_of_bits_to_extract,
            lwe_mask_size_after_bit_extraction,
            poly_size,
            glwe_mask_size,
            base_log_cb,
            level_cb,
            dispersion_cb_bsk,
            dispersion_cb_pfksk,
            log2_modulus,
        )
    } else if k1_type_id == TypeId::of::<TernaryKeyDistribution>()
        && k2_type_id == TypeId::of::<TernaryKeyDistribution>()
    {
        concrete_npe::estimate_wop_pbs_noise::<D1, D2, TernaryKeyKind, TernaryKeyKind>(
            number_of_bits_to_extract,
            lwe_mask_size_after_bit_extraction,
            poly_size,
            glwe_mask_size,
            base_log_cb,
            level_cb,
            dispersion_cb_bsk,
            dispersion_cb_pfksk,
            log2_modulus,
        )
    } else if k1_type_id == TypeId::of::<GaussianKeyDistribution>()
        && k2_type_id == TypeId::of::<GaussianKeyDistribution>()
    {
        concrete_npe::estimate_wop_pbs_noise::<D1, D2, GaussianKeyKind, GaussianKeyKind>(
            number_of_bits_to_extract,
            lwe_mask_size_after_bit_extraction,
            poly_size,
            glwe_mask_size,
            base_log_cb,
            level_cb,
            dispersion_cb_bsk,
            dispersion_cb_pfksk,
            log2_modulus,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
