use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweSecretKey, TransformsLweToGlweSecretKeyPrototype,
};
use crate::generation::synthesizing::{SynthesizesGlweSecretKey, SynthesizesLweSecretKey};
use crate::generation::{IntegerPrecision, Maker};
use concrete_commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
use concrete_core::prelude::{
    GlweSecretKeyEntity, GlweToLweSecretKeyTransformationEngine, LweSecretKeyEntity,
};

/// A fixture for the types implementing the `GlweToLweSecretKeyTransformationEngine` trait.
pub struct GlweToLweSecretKeyTransformationFixture;

#[derive(Debug)]
pub struct GlweToLweSecretKeyTransformationParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, Engine, InputSecretKey, OutputSecretKey>
    Fixture<Precision, Engine, (InputSecretKey, OutputSecretKey)>
    for GlweToLweSecretKeyTransformationFixture
where
    Precision: IntegerPrecision,
    Engine: GlweToLweSecretKeyTransformationEngine<InputSecretKey, OutputSecretKey>,
    InputSecretKey: GlweSecretKeyEntity,
    OutputSecretKey: LweSecretKeyEntity<KeyDistribution = InputSecretKey::KeyDistribution>,
    Maker: TransformsLweToGlweSecretKeyPrototype<Precision, OutputSecretKey::KeyDistribution>
        + SynthesizesLweSecretKey<Precision, OutputSecretKey>
        + SynthesizesGlweSecretKey<Precision, InputSecretKey>,
{
    type Parameters = GlweToLweSecretKeyTransformationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesGlweSecretKey<Precision, InputSecretKey::KeyDistribution>>::GlweSecretKeyProto,
    );
    type PreExecutionContext = (InputSecretKey,);
    type PostExecutionContext = (OutputSecretKey,);
    type Criteria = ();
    type Outcome = ((LweDimension, bool), (LweDimension, bool));

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweToLweSecretKeyTransformationParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(1024),
                },
                GlweToLweSecretKeyTransformationParameters {
                    glwe_dimension: GlweDimension(2),
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
        let proto_secret_key_in =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        (proto_secret_key_in,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key_in,) = sample_proto;
        let synth_secret_key_in = maker.synthesize_glwe_secret_key(proto_secret_key_in);
        (synth_secret_key_in,)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (sk_in,) = context;
        let sk_out = unsafe { engine.transform_glwe_secret_key_to_lwe_secret_key_unchecked(sk_in) };
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
        let glwe_dimension = parameters.glwe_dimension;
        let polynomial_size = parameters.polynomial_size;
        let expected_lwe_dimension = LweDimension(glwe_dimension.0 * polynomial_size.0);

        let actual_lwe_dimension = sk_out.lwe_dimension();

        let proto_out_lwe_key = maker.unsynthesize_lwe_secret_key(sk_out);
        let proto_out_lwe_key_roundtrip_to_glwe_key =
            maker.transform_lwe_secret_key_to_glwe_secret_key(&proto_out_lwe_key, polynomial_size);

        // Check that the roundtripped key is equal to the input sample
        let (proto_in_glwe_key,) = sample_proto;

        let roundtrip_is_identity_op =
            *proto_in_glwe_key == proto_out_lwe_key_roundtrip_to_glwe_key;
        (
            (expected_lwe_dimension, true),
            (actual_lwe_dimension, roundtrip_is_identity_op),
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
        // This checks LweDimension equality and key roundtrip identity
        expected == actual
    }
}
