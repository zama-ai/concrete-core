use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGgswCiphertext, PrototypesGlweCiphertext, PrototypesGlweSecretKey,
    PrototypesPlaintext, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{SynthesizesGgswCiphertext, SynthesizesGlweCiphertext};
use crate::generation::{
    BinaryKeyDistribution, GaussianKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker,
    TernaryKeyDistribution,
};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::commons::numeric::UnsignedInteger;
use concrete_core::prelude::{
    BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, DispersionParameter,
    GaussianKeyKind, GgswCiphertextEntity, GlweCiphertextEntity,
    GlweCiphertextsGgswCiphertextFusingCmuxEngine, GlweDimension, LogStandardDev, PolynomialSize,
    TernaryKeyKind, Variance,
};
use std::any::TypeId;

/// A fixture for the types implementing the `GlweCiphertextsGgswCiphertextFusingCmux` trait.
pub struct GlweCiphertextsGgswCiphertextFusingCmuxFixture;

#[derive(Debug)]
pub struct GlweCiphertextsGgswCiphertextFusingCmuxParameters {
    pub ggsw_noise: Variance,
    pub glwe_noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub ggsw_encrypted_value: usize,
    pub polynomial_size: PolynomialSize,
    pub decomposition_base_log: DecompositionBaseLog,
    pub decomposition_level_count: DecompositionLevelCount,
}

impl<Precision, KeyDistribution, Engine, GlweInput, GlweOutput, GgswInput>
    Fixture<Precision, (KeyDistribution,), Engine, (GlweInput, GlweOutput, GgswInput)>
    for GlweCiphertextsGgswCiphertextFusingCmuxFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: GlweCiphertextsGgswCiphertextFusingCmuxEngine<GlweInput, GlweOutput, GgswInput>,
    GlweInput: GlweCiphertextEntity,
    GlweOutput: GlweCiphertextEntity,
    GgswInput: GgswCiphertextEntity,
    Maker: SynthesizesGlweCiphertext<Precision, KeyDistribution, GlweInput>
        + SynthesizesGlweCiphertext<Precision, KeyDistribution, GlweOutput>
        + SynthesizesGgswCiphertext<Precision, KeyDistribution, GgswInput>,
{
    type Parameters = GlweCiphertextsGgswCiphertextFusingCmuxParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesPlaintext<Precision>>::PlaintextProto,
        <Maker as PrototypesGlweSecretKey<Precision, KeyDistribution>>::GlweSecretKeyProto,
        <Maker as PrototypesGgswCiphertext<Precision, KeyDistribution>>::GgswCiphertextProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesGlweCiphertext<Precision, KeyDistribution>>::GlweCiphertextProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesGlweCiphertext<Precision, KeyDistribution>>::GlweCiphertextProto,
    );
    type PreExecutionContext = (GlweInput, GgswInput, GlweOutput);
    type PostExecutionContext = (GlweInput, GgswInput, GlweOutput);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextsGgswCiphertextFusingCmuxParameters {
                    ggsw_noise: Variance(LogStandardDev(-20.).get_variance()),
                    glwe_noise: Variance(LogStandardDev(-25.).get_variance()),
                    glwe_dimension: GlweDimension(2),
                    ggsw_encrypted_value: 0,
                    polynomial_size: PolynomialSize(512),
                    decomposition_base_log: DecompositionBaseLog(7),
                    decomposition_level_count: DecompositionLevelCount(4),
                },
                GlweCiphertextsGgswCiphertextFusingCmuxParameters {
                    ggsw_noise: Variance(LogStandardDev(-20.).get_variance()),
                    glwe_noise: Variance(LogStandardDev(-25.).get_variance()),
                    glwe_dimension: GlweDimension(2),
                    ggsw_encrypted_value: 1,
                    polynomial_size: PolynomialSize(1024),
                    decomposition_base_log: DecompositionBaseLog(7),
                    decomposition_level_count: DecompositionLevelCount(4),
                },
                GlweCiphertextsGgswCiphertextFusingCmuxParameters {
                    ggsw_noise: Variance(LogStandardDev(-20.).get_variance()),
                    glwe_noise: Variance(LogStandardDev(-25.).get_variance()),
                    glwe_dimension: GlweDimension(2),
                    ggsw_encrypted_value: 2,
                    polynomial_size: PolynomialSize(2048),
                    decomposition_base_log: DecompositionBaseLog(7),
                    decomposition_level_count: DecompositionLevelCount(4),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        let raw_plaintext = match parameters.ggsw_encrypted_value {
            0 => Precision::Raw::zero(),
            1 => Precision::Raw::one(),
            2 => Precision::Raw::power_of_two(1),
            _ => Precision::Raw::zero(),
        };
        let proto_plaintext = maker.transform_raw_to_plaintext(&raw_plaintext);
        let proto_ggsw = maker.encrypt_plaintext_to_ggsw_ciphertext(
            &proto_secret_key,
            &proto_plaintext,
            parameters.ggsw_noise,
            parameters.decomposition_level_count,
            parameters.decomposition_base_log,
        );
        (proto_plaintext, proto_secret_key, proto_ggsw)
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (_, proto_secret_key, _) = repetition_proto;
        let raw_plaintext_vector0 = Precision::Raw::uniform_vec(parameters.polynomial_size.0);
        let raw_plaintext_vector1 = Precision::Raw::uniform_vec(parameters.polynomial_size.0);
        let proto_plaintext_vector0 =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector0);
        let proto_plaintext_vector1 =
            maker.transform_raw_vec_to_plaintext_vector(&raw_plaintext_vector1);
        let proto_output_glwe_ciphertext = maker.encrypt_plaintext_vector_to_glwe_ciphertext(
            proto_secret_key,
            &proto_plaintext_vector0,
            parameters.glwe_noise,
        );
        let proto_glwe_ciphertext = maker.encrypt_plaintext_vector_to_glwe_ciphertext(
            proto_secret_key,
            &proto_plaintext_vector1,
            parameters.glwe_noise,
        );
        (
            proto_plaintext_vector0,
            proto_output_glwe_ciphertext,
            proto_plaintext_vector1,
            proto_glwe_ciphertext,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, _, proto_ggsw_ciphertext) = repetition_proto;
        let (_, proto_output_glwe_ciphertext, _, proto_glwe_ciphertext) = sample_proto;
        let synth_glwe_ciphertext = maker.synthesize_glwe_ciphertext(proto_glwe_ciphertext);
        let synth_ggsw_ciphertext = maker.synthesize_ggsw_ciphertext(proto_ggsw_ciphertext);
        let synth_output_glwe_ciphertext =
            maker.synthesize_glwe_ciphertext(proto_output_glwe_ciphertext);
        (
            synth_glwe_ciphertext,
            synth_ggsw_ciphertext,
            synth_output_glwe_ciphertext,
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (mut glwe_ciphertext, ggsw_ciphertext, mut output_glwe_ciphertext) = context;
        unsafe {
            engine.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
                &mut output_glwe_ciphertext,
                &mut glwe_ciphertext,
                &ggsw_ciphertext,
            )
        };
        (glwe_ciphertext, ggsw_ciphertext, output_glwe_ciphertext)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (glwe_ciphertext, ggsw_ciphertext, output_glwe_ciphertext) = context;
        let (proto_plaintext, proto_secret_key, _) = repetition_proto;
        let (proto_input_plaintext_vector0, _, proto_input_plaintext_vector1, _) = sample_proto;
        let proto_output_glwe_ciphertext =
            maker.unsynthesize_glwe_ciphertext(output_glwe_ciphertext);
        maker.destroy_ggsw_ciphertext(ggsw_ciphertext);
        maker.destroy_glwe_ciphertext(glwe_ciphertext);
        let proto_output_plaintext_vector = maker.decrypt_glwe_ciphertext_to_plaintext_vector(
            proto_secret_key,
            &proto_output_glwe_ciphertext,
        );
        let raw_input_plaintext = maker.transform_plaintext_to_raw(proto_plaintext);
        let raw_input_plaintext_vector0 =
            maker.transform_plaintext_vector_to_raw_vec(proto_input_plaintext_vector0);
        let raw_input_plaintext_vector1 =
            maker.transform_plaintext_vector_to_raw_vec(proto_input_plaintext_vector1);
        let raw_input_plaintext_vector = raw_input_plaintext_vector0
            .iter()
            .zip(raw_input_plaintext_vector1.iter())
            .map(|(&v0, &v1)| v0.wrapping_add(v1.wrapping_sub(v0) * raw_input_plaintext))
            .collect();
        (
            raw_input_plaintext_vector,
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let output_variance = fix_estimate_cmux_noise_with_binary_ggsw::<
            Precision::Raw,
            Variance,
            Variance,
            Variance,
            KeyDistribution,
        >(
            parameters.polynomial_size,
            parameters.glwe_dimension,
            parameters.glwe_noise,
            parameters.glwe_noise,
            parameters.ggsw_noise,
            parameters.decomposition_base_log,
            parameters.decomposition_level_count,
        );
        (output_variance,)
    }

    fn verify(
        _parameters: &Self::Parameters,
        criteria: &Self::Criteria,
        outputs: &[Self::Outcome],
    ) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means = means.into_iter().flatten().collect::<Vec<_>>();
        let actual = actual.into_iter().flatten().collect::<Vec<_>>();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.
fn fix_estimate_cmux_noise_with_binary_ggsw<T, D1, D2, D3, K: KeyDistributionMarker>(
    poly_size: PolynomialSize,
    glwe_mask_size: GlweDimension,
    var_output_glwe: D1,
    var_glwe: D2,
    var_ggsw: D3,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K: KeyDistributionMarker,
{
    let k_type_id = TypeId::of::<K>();
    if k_type_id == TypeId::of::<BinaryKeyDistribution>() {
        concrete_npe::estimate_cmux_noise_with_binary_ggsw::<D1, D2, D3, BinaryKeyKind>(
            glwe_mask_size,
            poly_size,
            base_log,
            level,
            var_output_glwe,
            var_glwe,
            var_ggsw,
            T::BITS as u32,
        )
    } else if k_type_id == TypeId::of::<TernaryKeyDistribution>() {
        concrete_npe::estimate_cmux_noise_with_binary_ggsw::<D1, D2, D3, TernaryKeyKind>(
            glwe_mask_size,
            poly_size,
            base_log,
            level,
            var_output_glwe,
            var_glwe,
            var_ggsw,
            T::BITS as u32,
        )
    } else if k_type_id == TypeId::of::<GaussianKeyDistribution>() {
        concrete_npe::estimate_cmux_noise_with_binary_ggsw::<D1, D2, D3, GaussianKeyKind>(
            glwe_mask_size,
            poly_size,
            base_log,
            level,
            var_output_glwe,
            var_glwe,
            var_ggsw,
            T::BITS as u32,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
