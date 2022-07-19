use std::any::TypeId;
use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesGlweRelinearizationKey, PrototypesGlweSecretKey, PrototypesPlaintextVector, PrototypesGlweCiphertext};
use crate::generation::synthesizing::{SynthesizesGlweSecretKey, SynthesizesGlweRelinearizationKey, SynthesizesGlweCiphertext};
use crate::generation::{IntegerPrecision, Maker};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, LweDimension};
use concrete_core::prelude::{GlweSecretKeyEntity, GlweCiphertextLeveledMultiplicationEngine, GlweRelinearizationKeyEntity, ScalingFactor, GaussianKeyKind, TernaryKeyKind, BinaryKeyKind, DispersionParameter};
use concrete_core::prelude::markers::{BinaryKeyDistribution, GaussianKeyDistribution, KeyDistributionMarker, TernaryKeyDistribution};
use concrete_core::prelude::numeric::{CastInto, UnsignedInteger};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;

/// A fixture for the types implementing the `GlweCiphertextLeveledMultiplicationEngine` trait.
pub struct GlweCiphertextLeveledMultiplicationFixture;

#[derive(Debug)]
pub struct GlweCiphertextLeveledMultiplicationParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
    pub noise: Variance,
    pub scaling_factor: ScalingFactor,
}

impl<Precision, Engine, CiphertextIn, GlweRelinearizationKey, CiphertextOut>
Fixture<Precision, Engine, (CiphertextIn, GlweRelinearizationKey, CiphertextOut)>
for GlweCiphertextLeveledMultiplicationFixture
    where
        Precision: IntegerPrecision,
        Engine: GlweCiphertextLeveledMultiplicationEngine<CiphertextIn,
            GlweRelinearizationKey, CiphertextOut>,
        GlweRelinearizationKey: GlweRelinearizationKeyEntity<
            InputKeyDistribution = GlweSecretKey::KeyDistribution,
            OutputKeyDistribution = GlweRelinearizationKey::KeyDistribution,
        >,
        Maker: SynthesizesGlweCiphertext<Precision, CiphertextIn>
        + SynthesizesGlweCiphertext<Precision, CiphertextOut>
        + SynthesizesGlweRelinearizationKey<Precision, GlweRelinearizationKey>
{
    type Parameters = GlweCiphertextLeveledMultiplicationParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesGlweSecretKey<Precision, CiphertextIn::KeyDistribution>>::GlweSecretKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, 
            CiphertextIn::KeyDistribution>>::GlweRelinearizationKeyProto,
    );
    type SamplePrototypes =
    (<Maker as PrototypesGlweCiphertext<Precision, CiphertextIn::KeyDistribution>>::GlweCiphertextProto,
     <Maker as PrototypesGlweCiphertext<Precision,
         CiphertextIn::KeyDistribution>>::GlweCiphertextProto,
    );
    type PreExecutionContext = (CiphertextIn, CiphertextIn, GlweRelinearizationKey);
    type PostExecutionContext = (CiphertextIn, CiphertextIn, CiphertextOut, GlweRelinearizationKey);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextLeveledMultiplicationParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(1024),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
                    noise: Variance(0.00000001),
                    scaling_factor: ScalingFactor(16_u64),
                },
                GlweCiphertextLeveledMultiplicationParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(512),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
                    noise: Variance(0.00000001),
                    scaling_factor: ScalingFactor(16_u64),
                },
            ]
                .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key = <Maker as PrototypesGlweSecretKey<
            Precision,
            CiphertextIn::KeyDistribution,
        >>::new_glwe_secret_key(
            maker,
            parameters.glwe_dimension,
            parameters.polynomial_size,
        );
        let raw_plaintext_vector =
            Precision::Raw::uniform_n_msb_vec(5, parameters.polynomial_size.0);
        let proto_plaintext_vector1 =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let raw_plaintext_vector =
            Precision::Raw::uniform_n_msb_vec(5, parameters.polynomial_size.0);
        let proto_plaintext_vector2 =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let proto_relinearization_key = <Maker as PrototypesGlweRelinearizationKey<
            Precision,
            CiphertextIn::KeyDistribution,
        >>::new_glwe_relinearization_key(
            maker,
            &proto_secret_key,
            parameters.base_log,
            parameters.level,
            parameters.noise,
        );
        (
            proto_plaintext_vector1,
            proto_plaintext_vector2,
            proto_secret_key,
            proto_relinearization_key,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_plaintext_vector1, proto_plaintext_vector2, proto_secret_key) = repetition_proto;
        let proto_ciphertext1 =
            <Maker as PrototypesGlweCiphertext<
                Precision,
                CiphertextIn::KeyDistribution,
            >>::encrypt_plaintext_vector_to_glwe_ciphertext(
                maker,
                proto_secret_key,
                &proto_plaintext_vector1,
                parameters.noise,
            );
        let proto_ciphertext2 =
            <Maker as PrototypesGlweCiphertext<
                Precision,
                CiphertextIn::KeyDistribution,
            >>::encrypt_plaintext_vector_to_glwe_ciphertext(
                maker,
                proto_secret_key,
                &proto_plaintext_vector2,
                parameters.noise,
            );
        (proto_ciphertext1, proto_ciphertext2)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext1, proto_ciphertext2) = sample_proto;
        let ciphertext1 = <Maker as SynthesizesGlweCiphertext<
            Precision,
            CiphertextIn,
        >>::synthesize_glwe_ciphertext(
            maker,
            proto_ciphertext1);
        let ciphertext2 = <Maker as SynthesizesGlweCiphertext<
            Precision,
            CiphertextIn,
        >>::synthesize_glwe_ciphertext(
            maker,
            proto_ciphertext2);
        let rlk = <Maker as SynthesizesGlweRelinearizationKey<
            Precision,
            CiphertextIn,
        >>::synthesize_glwe_ciphertext(
            maker,
            proto_ciphertext2);
        
        (ciphertext1, ciphertext2, rlk)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (ct1, ct2, rlk) = context;
        let ct_out = unsafe {
            engine.compute_leveled_multiplication_glwe_ciphertexts(
                &ct1,
                &ct2,
                &rlk,
                parameters.scaling_factor,
            )
        };
        (ct1, ct2, ct_out, rlk)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_vector1, proto_plaintext_vector2, proto_secret_key) = repetition_proto;
        let (ct1, ct2, ct_out, rlk,) = context;
        let proto_output_ciphertext = <Maker as SynthesizesGlweCiphertext<
            Precision,
            CiphertextOut,
        >>::unsynthesize_glwe_ciphertext(
            maker,
            ct_out);
        maker.destroy_glwe_relinearization_key(rlk);
        maker.destroy_glwe_ciphertext(ct1);
        maker.destroy_glwe_ciphertext(ct2);
         let proto_output_plaintext_vector =
            <Maker as PrototypesGlweCiphertext<
                Precision,
                CiphertextOut::KeyDistribution,
            >>::decrypt_glwe_ciphertext_to_plaintext_vector(
                maker,
                &proto_secret_key,
                &proto_output_ciphertext,
            );
        let raw_input_plaintext_vector1 =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector1);
        let raw_input_plaintext_vector2 =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector2);
        // FIXME: check the formula below, this one was the tensor product one
        let raw_output_plaintext_vector: Vec<Precision::Raw> = raw_input_plaintext_vector1
            .iter()
            .zip(raw_input_plaintext_vector2.iter())
            .map(|(&a, &b)| {
                <f64 as CastInto<Precision::Raw>>::cast_into(
                    <Precision::Raw as CastInto<f64>>::cast_into(a)
                        * <Precision::Raw as CastInto<f64>>::cast_into(b)
                        / parameters.scaling_factor.0 as f64,
                )
            })
            .collect();

        (
            raw_output_plaintext_vector,
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let msg_bound = (1 << 5) as f64;
        let output_variance = fix_estimate_multiplication_noise::<
            Precision::Raw,
            Variance,
            Variance,
            Variance,
            CiphertextIn::KeyDistribution,
        >(
            parameters.polynomial_size,
            parameters.glwe_dimension,
            parameters.noise,
            parameters.noise,
            parameters.scaling_factor.0 as f64,
            parameters.scaling_factor.0 as f64,
            msg_bound,
            msg_bound,
            parameters.noise,
            parameters.base_log,
            parameters.level,
        );
        (output_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.

fn fix_estimate_multiplication_noise<T, D1, D2, D3, K>(
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    var_glwe1: D1,
    var_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
    var_rlk: D3,
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
        concrete_npe::estimate_multiplication_noise::<T, D1, D2, D3, BinaryKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
            var_rlk,
            base_log,
            level,
        )
    } else if k_type_id == TypeId::of::<TernaryKeyDistribution>() {
        concrete_npe::estimate_multiplication_noise::<T, D1, D2, D3, TernaryKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
            var_rlk,
            base_log,
            level,
        )
    } else if k_type_id == TypeId::of::<GaussianKeyDistribution>() {
        concrete_npe::estimate_multiplication_noise::<T, D1, D2, D3, GaussianKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
            var_rlk,
            base_log,
            level,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
