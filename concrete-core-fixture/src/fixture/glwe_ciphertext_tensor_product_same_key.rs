use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertext, PrototypesGlweSecretKey, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertext, SynthesizesGlweSecretKey, SynthesizesTensorProductGlweSecretKey,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::markers::{
    BinaryKeyDistribution, GaussianKeyDistribution, KeyDistributionMarker,
    TensorProductKeyDistribution, TernaryKeyDistribution,
};
use concrete_core::prelude::numeric::{CastInto, UnsignedInteger};
use concrete_core::prelude::{
    BinaryKeyKind, DispersionParameter, GaussianKeyKind, GlweCiphertextEntity,
    GlweCiphertextTensorProductSameKeyEngine, GlweSecretKeyEntity, ScalingFactor, TernaryKeyKind,
};
use std::any::TypeId;

/// A fixture for the types implementing the `GlweCiphertextTensorProductSameKeyEngine` trait.
pub struct GlweCiphertextTensorProductSameKeyFixture;

#[derive(Debug)]
pub struct GlweCiphertextTensorProductSameKeyParameters {
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,
    pub noise: Variance,
    pub scaling_factor: ScalingFactor,
    pub msg_n_msb: usize,
}

impl<Precision, Engine, CiphertextIn1, CiphertextIn2, CiphertextOut, TensorProductKey>
    Fixture<
        Precision,
        Engine,
        (
            CiphertextIn1,
            CiphertextIn2,
            CiphertextOut,
            TensorProductKey,
        ),
    > for GlweCiphertextTensorProductSameKeyFixture
where
    Precision: IntegerPrecision,
    Engine: GlweCiphertextTensorProductSameKeyEngine<CiphertextIn1, CiphertextIn2, CiphertextOut>,
    CiphertextIn1: GlweCiphertextEntity<KeyDistribution = BinaryKeyDistribution>,
    CiphertextIn2: GlweCiphertextEntity<KeyDistribution = BinaryKeyDistribution>,
    CiphertextOut: GlweCiphertextEntity<KeyDistribution = TensorProductKeyDistribution>,
    TensorProductKey: GlweSecretKeyEntity<KeyDistribution = TensorProductKeyDistribution>,
    Maker: SynthesizesGlweCiphertext<Precision, CiphertextIn1>
        + SynthesizesGlweCiphertext<Precision, CiphertextIn2>
        + SynthesizesGlweCiphertext<Precision, CiphertextOut>
        + SynthesizesTensorProductGlweSecretKey<
            Precision,
            CiphertextIn1::KeyDistribution,
            TensorProductKey,
        > + SynthesizesGlweSecretKey<Precision, TensorProductKey>,
{
    type Parameters = GlweCiphertextTensorProductSameKeyParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesGlweSecretKey<Precision, CiphertextIn1::KeyDistribution>>::GlweSecretKeyProto,
    );
    type SamplePrototypes =
    (<Maker as PrototypesGlweCiphertext<Precision, CiphertextIn1::KeyDistribution>>::GlweCiphertextProto,
     <Maker as PrototypesGlweCiphertext<Precision,
         CiphertextIn1::KeyDistribution>>::GlweCiphertextProto,
    );

    type PreExecutionContext = (CiphertextIn1, CiphertextIn2);
    type PostExecutionContext = (CiphertextIn1, CiphertextIn2, CiphertextOut);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextTensorProductSameKeyParameters {
                    noise: Variance(0.00000001),
                    scaling_factor: ScalingFactor(16_u64),
                    glwe_dimension: GlweDimension(200),
                    polynomial_size: PolynomialSize(256),
                    msg_n_msb: 5,
                },
                GlweCiphertextTensorProductSameKeyParameters {
                    noise: Variance(0.00000001),
                    scaling_factor: ScalingFactor(16_u64),
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(256),
                    msg_n_msb: 5,
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key = <Maker as PrototypesGlweSecretKey<
            Precision,
            CiphertextIn1::KeyDistribution,
        >>::new_glwe_secret_key(
            maker, parameters.glwe_dimension, parameters.polynomial_size
        );
        let raw_plaintext_vector =
            Precision::Raw::uniform_n_msb_vec(parameters.msg_n_msb, parameters.polynomial_size.0);
        let proto_plaintext_vector1 =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let raw_plaintext_vector =
            Precision::Raw::uniform_n_msb_vec(parameters.msg_n_msb, parameters.polynomial_size.0);
        let proto_plaintext_vector2 =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        (
            proto_plaintext_vector1,
            proto_plaintext_vector2,
            proto_secret_key,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_plaintext_vector1, proto_plaintext_vector2, proto_secret_key) = repetition_proto;
        let proto_ciphertext1 = <Maker as PrototypesGlweCiphertext<
            Precision,
            CiphertextIn1::KeyDistribution,
        >>::encrypt_plaintext_vector_to_glwe_ciphertext(
            maker,
            proto_secret_key,
            proto_plaintext_vector1,
            parameters.noise,
        );
        let proto_ciphertext2 = <Maker as PrototypesGlweCiphertext<
            Precision,
            CiphertextIn1::KeyDistribution,
        >>::encrypt_plaintext_vector_to_glwe_ciphertext(
            maker,
            proto_secret_key,
            proto_plaintext_vector2,
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
            CiphertextIn1,
        >>::synthesize_glwe_ciphertext(
            maker,
            proto_ciphertext1);
        let ciphertext2 = <Maker as SynthesizesGlweCiphertext<
            Precision,
            CiphertextIn2,
        >>::synthesize_glwe_ciphertext(
            maker,
            proto_ciphertext2);

        (ciphertext1, ciphertext2)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (proto_ciphertext1, proto_ciphertext2) = context;
        let output_ciphertext = unsafe {
            engine.tensor_product_glwe_ciphertext_same_key_unchecked(
                &proto_ciphertext1,
                &proto_ciphertext2,
                parameters.scaling_factor,
            )
        };
        (proto_ciphertext1, proto_ciphertext2, output_ciphertext)
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_vector1, proto_plaintext_vector2, proto_secret_key) = repetition_proto;
        let (input_ciphertext_1, input_ciphertext_2, output_ciphertext) = context;

        // Convert the tensor product result back to the standard domain
        let proto_output_ciphertext = <Maker as SynthesizesGlweCiphertext<
            Precision,
            CiphertextOut,
        >>::unsynthesize_glwe_ciphertext(
            maker, output_ciphertext
        );
        // Destroy the input ciphertexts (the unsynthesize should handle any memory cleaning if
        // necessary)
        maker.destroy_glwe_ciphertext(input_ciphertext_1);
        maker.destroy_glwe_ciphertext(input_ciphertext_2);
        // Create a tensor product key
        let output_key =
            <Maker as SynthesizesTensorProductGlweSecretKey<
                Precision,
                CiphertextIn1::KeyDistribution,
                TensorProductKey,
            >>::synthesize_tensor_product_glwe_secret_key(maker, proto_secret_key);
        // Convert the tensor product key to a prototype data
        let proto_output_key = <Maker as SynthesizesGlweSecretKey<
            Precision,
            TensorProductKey,
        >>::unsynthesize_glwe_secret_key(
            maker,
            output_key);

        let proto_output_plaintext_vector = <Maker as PrototypesGlweCiphertext<
            Precision,
            CiphertextOut::KeyDistribution,
        >>::decrypt_glwe_ciphertext_to_plaintext_vector(
            maker,
            &proto_output_key,
            &proto_output_ciphertext,
        );
        let raw_input_plaintext_vector1 =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector1);
        let raw_input_plaintext_vector2 =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector2);

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
        let msg_bound = (1 << parameters.msg_n_msb) as f64;
        let output_variance = fix_estimate_tensor_product_noise::<
            Precision::Raw,
            Variance,
            Variance,
            CiphertextIn1::KeyDistribution,
        >(
            parameters.polynomial_size,
            parameters.glwe_dimension,
            parameters.noise,
            parameters.noise,
            parameters.scaling_factor.0 as f64,
            parameters.scaling_factor.0 as f64,
            msg_bound,
            msg_bound,
        );
        (output_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        //correct
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        // plaintext without an error
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        // what we get from decryption
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.

#[allow(clippy::too_many_arguments)]
fn fix_estimate_tensor_product_noise<T, D1, D2, K>(
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    var_glwe1: D1,
    var_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDistributionMarker,
{
    let k_type_id = TypeId::of::<K>();
    if k_type_id == TypeId::of::<BinaryKeyDistribution>() {
        concrete_npe::estimate_tensor_product_noise::<T, D1, D2, BinaryKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
        )
    } else if k_type_id == TypeId::of::<TernaryKeyDistribution>() {
        concrete_npe::estimate_tensor_product_noise::<T, D1, D2, TernaryKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
        )
    } else if k_type_id == TypeId::of::<GaussianKeyDistribution>() {
        concrete_npe::estimate_tensor_product_noise::<T, D1, D2, GaussianKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
