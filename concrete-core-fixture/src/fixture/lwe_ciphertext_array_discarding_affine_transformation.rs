use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesCleartextArray, PrototypesLweCiphertext, PrototypesLweCiphertextArray,
    PrototypesLweSecretKey, PrototypesPlaintext, PrototypesPlaintextArray,
};
use crate::generation::synthesizing::{
    SynthesizesCleartextArray, SynthesizesLweCiphertext, SynthesizesLweCiphertextArray,
    SynthesizesPlaintext,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_core::commons::numeric::UnsignedInteger;
use concrete_core::prelude::{
    CleartextArrayEntity, DispersionParameter, LogStandardDev,
    LweCiphertextArrayDiscardingAffineTransformationEngine, LweCiphertextArrayEntity,
    LweCiphertextCount, LweCiphertextEntity, LweDimension, PlaintextEntity, Variance,
};

/// A fixture for the types implementing the
/// `LweCiphertextArrayDiscardingAffineTransformationEngine` trait.
pub struct LweCiphertextArrayDiscardingAffineTransformationFixture;

#[derive(Debug)]
pub struct LweCiphertextArrayDiscardingAffineTransformationParameters {
    pub nb_ct: LweCiphertextCount,
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

#[allow(clippy::type_complexity)]
impl<
        Precision,
        KeyDistribution,
        Engine,
        CiphertextArray,
        CleartextArray,
        Plaintext,
        OutputCiphertext,
    >
    Fixture<
        Precision,
        (KeyDistribution,),
        Engine,
        (CiphertextArray, CleartextArray, Plaintext, OutputCiphertext),
    > for LweCiphertextArrayDiscardingAffineTransformationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweCiphertextArrayDiscardingAffineTransformationEngine<
        CiphertextArray,
        CleartextArray,
        Plaintext,
        OutputCiphertext,
    >,
    CiphertextArray: LweCiphertextArrayEntity,
    CleartextArray: CleartextArrayEntity,
    Plaintext: PlaintextEntity,
    OutputCiphertext: LweCiphertextEntity,
    Maker: SynthesizesLweCiphertextArray<Precision, KeyDistribution, CiphertextArray>
        + SynthesizesCleartextArray<Precision, CleartextArray>
        + SynthesizesPlaintext<Precision, Plaintext>
        + SynthesizesLweCiphertext<Precision, KeyDistribution, OutputCiphertext>,
{
    type Parameters = LweCiphertextArrayDiscardingAffineTransformationParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesCleartextArray<Precision>>::CleartextArrayProto,
        <Maker as PrototypesPlaintext<Precision>>::PlaintextProto,
    );
    type SamplePrototypes = (
        <Maker as PrototypesLweCiphertext<Precision, KeyDistribution>>::LweCiphertextProto,
        <Maker as PrototypesPlaintextArray<Precision>>::PlaintextArrayProto,
        <Maker as PrototypesLweCiphertextArray<Precision, KeyDistribution>>::LweCiphertextArrayProto,
    );
    type PreExecutionContext = (OutputCiphertext, CiphertextArray, CleartextArray, Plaintext);
    type PostExecutionContext = (OutputCiphertext, CiphertextArray, CleartextArray, Plaintext);
    type Criteria = (Variance,);
    type Outcome = (Precision::Raw, Precision::Raw);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![LweCiphertextArrayDiscardingAffineTransformationParameters {
                nb_ct: LweCiphertextCount(100),
                noise: Variance(LogStandardDev::from_log_standard_dev(-25.).get_variance()),
                lwe_dimension: LweDimension(1000),
            }]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key = maker.new_lwe_secret_key(parameters.lwe_dimension);
        let raw_cleartext_array =
            Precision::Raw::uniform_zero_centered_vec(512, parameters.nb_ct.0);
        let raw_plaintext = Precision::Raw::uniform_between(0..1024usize);
        let proto_cleartext_array =
            maker.transform_raw_vec_to_cleartext_array(raw_cleartext_array.as_slice());
        let proto_plaintext = maker.transform_raw_to_plaintext(&raw_plaintext);
        (proto_secret_key, proto_cleartext_array, proto_plaintext)
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_secret_key, ..) = repetition_proto;
        let raw_plaintext_array = Precision::Raw::uniform_vec(parameters.nb_ct.0);
        let proto_plaintext_array =
            maker.transform_raw_vec_to_plaintext_array(raw_plaintext_array.as_slice());
        let proto_ciphertext_array = maker.encrypt_plaintext_array_to_lwe_ciphertext_array(
            proto_secret_key,
            &proto_plaintext_array,
            parameters.noise,
        );
        let proto_output_ciphertext =
            maker.trivially_encrypt_zero_to_lwe_ciphertext(parameters.lwe_dimension);
        (
            proto_output_ciphertext,
            proto_plaintext_array,
            proto_ciphertext_array,
        )
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, proto_cleartext_array, proto_plaintext) = repetition_proto;
        let (proto_output_ciphertext, _, proto_ciphertext_array) = sample_proto;
        (
            maker.synthesize_lwe_ciphertext(proto_output_ciphertext),
            maker.synthesize_lwe_ciphertext_array(proto_ciphertext_array),
            maker.synthesize_cleartext_array(proto_cleartext_array),
            maker.synthesize_plaintext(proto_plaintext),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (mut output_ciphertext, ciphertext_array, weights, bias) = context;
        unsafe {
            engine.discard_affine_transform_lwe_ciphertext_array_unchecked(
                &mut output_ciphertext,
                &ciphertext_array,
                &weights,
                &bias,
            )
        };
        (output_ciphertext, ciphertext_array, weights, bias)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (output_ciphertext, ciphertext_array, weights, bias) = context;
        let (proto_secret_key, prototype_cleartext_array, prototype_plaintext) = repetition_proto;
        let (_, proto_plaintext_array, _) = sample_proto;
        let proto_output_ciphertext = maker.unsynthesize_lwe_ciphertext(output_ciphertext);
        let proto_output_plaintext =
            maker.decrypt_lwe_ciphertext_to_plaintext(proto_secret_key, &proto_output_ciphertext);
        let raw_plaintext_array = maker.transform_plaintext_array_to_raw_vec(proto_plaintext_array);
        let raw_cleartext_array =
            maker.transform_cleartext_array_to_raw_vec(prototype_cleartext_array);
        let raw_bias = maker.transform_plaintext_to_raw(prototype_plaintext);
        let predicted_output = raw_plaintext_array
            .iter()
            .zip(raw_cleartext_array.iter())
            .fold(raw_bias, |a, (c, w)| a.wrapping_add(c.wrapping_mul(*w)));
        maker.destroy_lwe_ciphertext_array(ciphertext_array);
        maker.destroy_cleartext_array(weights);
        maker.destroy_plaintext(bias);
        (
            predicted_output,
            maker.transform_plaintext_to_raw(&proto_output_plaintext),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let (_, proto_cleartext_array, _) = repetition_proto;
        let raw_weight_array = maker.transform_cleartext_array_to_raw_vec(proto_cleartext_array);
        let predicted_variance: Variance =
            concrete_npe::estimate_weighted_sum_noise::<Precision::Raw, _>(
                &vec![parameters.noise; parameters.nb_ct.0],
                &raw_weight_array,
            );
        (predicted_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}
