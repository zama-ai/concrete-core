use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesCleartextVector, PrototypesGlweCiphertext, PrototypesGlweSecretKey,
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesPlaintextVector,
    PrototypesPrivateFunctionalPackingKeyswitchKey,
};
use crate::generation::synthesizing::{
    SynthesizesCleartextVector, SynthesizesGlweCiphertext, SynthesizesLweCiphertextVector,
    SynthesizesPrivateFunctionalPackingKeyswitchKey,
};
use crate::generation::{
    BinaryKeyDistribution, GaussianKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker,
    TernaryKeyDistribution,
};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::{StandardDev, Variance};
use concrete_commons::key_kinds::{BinaryKeyKind, GaussianKeyKind, TernaryKeyKind};
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::commons::math::polynomial::Polynomial;
use concrete_core::prelude::{
    CleartextVectorEntity, DispersionParameter, GlweCiphertextEntity, LogStandardDev,
    LweCiphertextCount, LweCiphertextVectorEntity,
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine,
    PrivateFunctionalPackingKeyswitchKeyEntity,
};
use std::any::TypeId;

/// A fixture for the types implementing the
/// `LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine` trait.
pub struct LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchParameters {
    pub input_lwe_noise: Variance,
    pub pfpksk_noise: StandardDev,
    pub input_lwe_dimension: LweDimension,
    pub input_lwe_count: LweCiphertextCount,
    pub output_glwe_dimension: GlweDimension,
    pub output_polynomial_size: PolynomialSize,
    pub decomposition_level: DecompositionLevelCount,
    pub decomposition_base_log: DecompositionBaseLog,
    pub function_log_scalar: usize,
}

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        InputCiphertextVector,
        PrivateFunctionalPackingKeyswitchKey,
        OutputCiphertext,
        CleartextVector,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (
            InputCiphertextVector,
            PrivateFunctionalPackingKeyswitchKey,
            OutputCiphertext,
            CleartextVector,
        ),
    > for LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
        PrivateFunctionalPackingKeyswitchKey,
        InputCiphertextVector,
        OutputCiphertext,
    >,
    InputCiphertextVector: LweCiphertextVectorEntity,
    PrivateFunctionalPackingKeyswitchKey: PrivateFunctionalPackingKeyswitchKeyEntity,
    OutputCiphertext: GlweCiphertextEntity,
    CleartextVector: CleartextVectorEntity,
    Maker: SynthesizesLweCiphertextVector<Precision, InputKeyDistribution, InputCiphertextVector>
        + SynthesizesGlweCiphertext<Precision, OutputKeyDistribution, OutputCiphertext>
        + SynthesizesCleartextVector<Precision, CleartextVector>
        + SynthesizesPrivateFunctionalPackingKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            PrivateFunctionalPackingKeyswitchKey,
        >,
{
    type Parameters =
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesPrivateFunctionalPackingKeyswitchKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::PrivateFunctionalPackingKeyswitchKeyProto,
        <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, OutputKeyDistribution>>::GlweSecretKeyProto,
        <Maker as PrototypesCleartextVector<Precision>>::CleartextVectorProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesLweCiphertextVector<
            Precision,
            InputKeyDistribution,
        >>::LweCiphertextVectorProto,
        <Maker as PrototypesGlweCiphertext<
            Precision,
            OutputKeyDistribution,
        >>::GlweCiphertextProto,
    );
    type PreExecutionContext = (
        OutputCiphertext,
        InputCiphertextVector,
        PrivateFunctionalPackingKeyswitchKey,
    );
    type PostExecutionContext = (
        OutputCiphertext,
        InputCiphertextVector,
        PrivateFunctionalPackingKeyswitchKey,
    );
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);
    type Criteria = (Variance,);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchParameters {
                    input_lwe_noise: Variance(
                        LogStandardDev::from_log_standard_dev(-10.).get_variance(),
                    ),
                    pfpksk_noise: StandardDev(
                        LogStandardDev::from_log_standard_dev(-25.).get_standard_dev(),
                    ),
                    input_lwe_dimension: LweDimension(200),
                    input_lwe_count: LweCiphertextCount(10),
                    output_glwe_dimension: GlweDimension(1),
                    output_polynomial_size: PolynomialSize(256),
                    decomposition_level: DecompositionLevelCount(3),
                    decomposition_base_log: DecompositionBaseLog(7),
                    function_log_scalar: 0,
                },
                LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchParameters {
                    input_lwe_noise: Variance(
                        LogStandardDev::from_log_standard_dev(-10.).get_variance(),
                    ),
                    pfpksk_noise: StandardDev(
                        LogStandardDev::from_log_standard_dev(-25.).get_standard_dev(),
                    ),
                    input_lwe_dimension: LweDimension(200),
                    input_lwe_count: LweCiphertextCount(10),
                    output_glwe_dimension: GlweDimension(2),
                    output_polynomial_size: PolynomialSize(256),
                    decomposition_level: DecompositionLevelCount(3),
                    decomposition_base_log: DecompositionBaseLog(7),
                    function_log_scalar: 4,
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key_input =
            <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::new_lwe_secret_key(
                maker,
                parameters.input_lwe_dimension,
            );
        let proto_secret_key_output = <Maker as PrototypesGlweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::new_glwe_secret_key(
            maker,
            parameters.output_glwe_dimension,
            parameters.output_polynomial_size,
        );
        let raw_cleartext_vector =
            Precision::Raw::uniform_zero_centered_vec(1, parameters.output_polynomial_size.0);
        let proto_cleartext_vector =
            maker.transform_raw_vec_to_cleartext_vector(&raw_cleartext_vector);
        let scalar = Precision::Raw::power_of_two(parameters.function_log_scalar);

        let proto_pfpksk = maker.new_private_functional_packing_keyswitch_key(
            &proto_secret_key_input,
            &proto_secret_key_output,
            parameters.decomposition_level,
            parameters.decomposition_base_log,
            parameters.pfpksk_noise,
            &|x| scalar * x,
            &proto_cleartext_vector,
        );
        (
            proto_pfpksk,
            proto_secret_key_input,
            proto_secret_key_output,
            proto_cleartext_vector,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (_, proto_input_secret_key, _, _) = repetition_proto;
        let raw_plaintext_vector = Precision::Raw::uniform_vec(parameters.input_lwe_count.0);
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_input_ciphertext_vector = <Maker as PrototypesLweCiphertextVector<
            Precision,
            InputKeyDistribution,
        >>::encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            maker,
            proto_input_secret_key,
            &proto_plaintext_vector,
            parameters.input_lwe_noise,
        );
        let proto_output_ciphertext = <Maker as PrototypesGlweCiphertext<
            Precision,
            OutputKeyDistribution,
        >>::trivially_encrypt_zeros_to_glwe_ciphertext(
            maker,
            parameters.output_glwe_dimension,
            parameters.output_polynomial_size,
        );
        (
            proto_plaintext_vector,
            proto_input_ciphertext_vector,
            proto_output_ciphertext,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_private_functional_packing_keyswitch_key, ..) = repetition_proto;
        let (_, proto_input_ciphertext_vector, proto_output_ciphertext) = sample_proto;
        let synth_private_functional_packing_keyswitch_key = maker
            .synthesize_private_functional_packing_keyswitch_key(
                proto_private_functional_packing_keyswitch_key,
            );
        let synth_input_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(proto_input_ciphertext_vector);
        let synth_output_ciphertext = maker.synthesize_glwe_ciphertext(proto_output_ciphertext);
        (
            synth_output_ciphertext,
            synth_input_ciphertext_vector,
            synth_private_functional_packing_keyswitch_key,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (mut output_ciphertext, input_ciphertext_vector, pfpksk) = context;
        unsafe {
            engine.discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
                &mut output_ciphertext,
                &input_ciphertext_vector,
                &pfpksk,
            );
        };
        (output_ciphertext, input_ciphertext_vector, pfpksk)
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (output_ciphertext, input_ciphertext, keyswitch_key) = context;
        let (_, _, proto_output_secret_key, proto_cleartext_vector) = repetition_proto;
        let (proto_plaintext_vector, ..) = sample_proto;
        let proto_output_ciphertext = maker.unsynthesize_glwe_ciphertext(output_ciphertext);
        let proto_output_plaintext = maker.decrypt_glwe_ciphertext_to_plaintext_vector(
            proto_output_secret_key,
            &proto_output_ciphertext,
        );
        let raw_cleartext_vector =
            maker.transform_cleartext_vector_to_raw_vec(proto_cleartext_vector);
        let function_poly = Polynomial::from_container(raw_cleartext_vector);
        let raw_input_vector = maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector);
        let input_poly = Polynomial::from_container(raw_input_vector);
        let mut raw_result =
            Polynomial::allocate(Precision::Raw::zero(), parameters.output_polynomial_size);
        raw_result.fill_with_wrapping_mul(&function_poly, &input_poly);
        maker.destroy_lwe_ciphertext_vector(input_ciphertext);
        maker.destroy_private_functional_packing_keyswitch_key(keyswitch_key);
        (
            raw_result
                .coefficient_iter()
                .take(parameters.output_polynomial_size.0)
                .cloned()
                .collect::<Vec<Precision::Raw>>(),
            maker
                .transform_plaintext_vector_to_raw_vec(&proto_output_plaintext)
                .iter()
                .take(parameters.output_polynomial_size.0)
                .cloned()
                .collect::<Vec<Precision::Raw>>(),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let polynomial_infinity_norm = 1.;
        let predicted_variance =
            fix_estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
                Precision::Raw,
                _,
                _,
                OutputKeyDistribution,
            >(
                parameters.input_lwe_dimension,
                parameters.input_lwe_noise,
                parameters.pfpksk_noise,
                parameters.decomposition_base_log,
                parameters.decomposition_level,
                2_f64.powi(parameters.function_log_scalar as i32) * polynomial_infinity_norm,
            );
        (Variance(
            predicted_variance.0 * parameters.input_lwe_count.0 as f64,
        ),)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means = means
            .iter()
            .flat_map(|r| r.iter())
            .copied()
            .collect::<Vec<_>>();
        let actual = actual
            .iter()
            .flat_map(|r| r.iter())
            .copied()
            .collect::<Vec<_>>();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.
pub(crate) fn fix_estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms<
    T,
    D1,
    D2,
    K,
>(
    lwe_mask_size: LweDimension,
    dispersion_lwe: D1,
    dispersion_ksk: D2,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    function_lipschitz_bound: f64,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDistributionMarker,
{
    let k_type_id = TypeId::of::<K>();
    if k_type_id == TypeId::of::<BinaryKeyDistribution>() {
        concrete_npe::estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
            T,
            D1,
            D2,
            BinaryKeyKind,
        >(
            lwe_mask_size,
            dispersion_lwe,
            dispersion_ksk,
            base_log,
            level,
            function_lipschitz_bound,
        )
    } else if k_type_id == TypeId::of::<TernaryKeyDistribution>() {
        concrete_npe::estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
            T,
            D1,
            D2,
            TernaryKeyKind,
        >(
            lwe_mask_size,
            dispersion_lwe,
            dispersion_ksk,
            base_log,
            level,
            function_lipschitz_bound,
        )
    } else if k_type_id == TypeId::of::<GaussianKeyDistribution>() {
        concrete_npe::estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
            T,
            D1,
            D2,
            GaussianKeyKind,
        >(
            lwe_mask_size,
            dispersion_lwe,
            dispersion_ksk,
            base_log,
            level,
            function_lipschitz_bound,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
