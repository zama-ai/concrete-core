use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesGlweSecretKey, PrototypesLweSecretKey};
use crate::generation::synthesizing::{SynthesizesGlweSecretKey, SynthesizesLweSecretKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_core::prelude::{
    GlweDimension, GlweSecretKeyEntity, LweDimension, LweSecretKeyEntity,
    LweToGlweSecretKeyTransformationEngine, PolynomialSize,
};

/// A fixture for the types implementing the `LweToGlweSecretKeyTransformationEngine` trait.
pub struct LweToGlweSecretKeyTransformationFixture;

#[derive(Debug)]
pub struct LweToGlweSecretKeyTransformationParameters {
    pub lwe_dimension: LweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, KeyDistribution, Engine, InputSecretKey, OutputSecretKey>
    Fixture<Precision, (KeyDistribution,), Engine, (InputSecretKey, OutputSecretKey)>
    for LweToGlweSecretKeyTransformationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LweToGlweSecretKeyTransformationEngine<InputSecretKey, OutputSecretKey>,
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: GlweSecretKeyEntity,
    Maker: SynthesizesGlweSecretKey<Precision, KeyDistribution, OutputSecretKey>
        + SynthesizesLweSecretKey<Precision, KeyDistribution, InputSecretKey>,
{
    type Parameters = LweToGlweSecretKeyTransformationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type PreExecutionContext = (InputSecretKey,);
    type PostExecutionContext = (OutputSecretKey,);
    type Criteria = ();
    type Outcome = (
        (GlweDimension, PolynomialSize, bool),
        (GlweDimension, PolynomialSize, bool),
    );

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweToGlweSecretKeyTransformationParameters {
                    lwe_dimension: LweDimension(1024),
                    polynomial_size: PolynomialSize(1024),
                },
                LweToGlweSecretKeyTransformationParameters {
                    lwe_dimension: LweDimension(4096),
                    polynomial_size: PolynomialSize(2048),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let proto_secret_key_in = maker.new_lwe_secret_key(parameters.lwe_dimension);
        (proto_secret_key_in,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key_in,) = sample_proto;
        let synth_secret_key_in = maker.synthesize_lwe_secret_key(proto_secret_key_in);
        (synth_secret_key_in,)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (sk_in,) = context;
        let polynomial_size = parameters.polynomial_size;
        let sk_out = unsafe {
            engine.transform_lwe_secret_key_to_glwe_secret_key_unchecked(sk_in, polynomial_size)
        };
        (sk_out,)
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (sk_out,) = context;
        let lwe_dimension = parameters.lwe_dimension;
        let polynomial_size = parameters.polynomial_size;
        let expected_glwe_dimension = GlweDimension(lwe_dimension.0 / polynomial_size.0);
        let expected_polynomial_size = polynomial_size;

        let actual_glwe_dimension = sk_out.glwe_dimension();
        let actual_polynomial_size = sk_out.polynomial_size();

        let proto_out_glwe_key = maker.unsynthesize_glwe_secret_key(sk_out);
        let proto_out_glwe_key_roundtrip_to_lwe_key =
            maker.transform_glwe_secret_key_to_lwe_secret_key(&proto_out_glwe_key);

        // Check that the roundtripped key is equal to the input sample
        let (proto_in_lwe_key,) = sample_proto;

        let roundtrip_is_identity_op = *proto_in_lwe_key == proto_out_glwe_key_roundtrip_to_lwe_key;

        (
            (expected_glwe_dimension, expected_polynomial_size, true),
            (
                actual_glwe_dimension,
                actual_polynomial_size,
                roundtrip_is_identity_op,
            ),
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(_criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (expected, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        // This checks GlweDimension equality, PolynomialSize equality and key roundtrip identity
        expected == actual
    }
}
