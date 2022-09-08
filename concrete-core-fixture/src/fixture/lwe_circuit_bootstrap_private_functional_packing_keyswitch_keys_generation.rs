use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesGlweSecretKey, PrototypesLweSecretKey};
use crate::generation::synthesizing::{
    SynthesizesGlweSecretKey, SynthesizesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
    SynthesizesLweSecretKey,
};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSecretKeyEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine, LweDimension,
    LweSecretKeyEntity, PolynomialSize, Variance,
};

/// A fixture for the types implementing the
/// `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine` trait.
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationFixture;

#[derive(Debug)]
pub struct LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationParameters {
    pub noise: Variance,
    pub lwe_dimension_in: LweDimension,
    pub glwe_dimension_out: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
}

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        InputSecretKey,
        OutputSecretKey,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (
            InputSecretKey,
            OutputSecretKey,
            LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
        ),
    > for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine<
        InputSecretKey,
        OutputSecretKey,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
    >,
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: GlweSecretKeyEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys:
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    Maker: SynthesizesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
        > + SynthesizesLweSecretKey<Precision, InputKeyDistribution, InputSecretKey>
        + SynthesizesGlweSecretKey<Precision, OutputKeyDistribution, OutputSecretKey>,
{
    type Parameters = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        <Maker as PrototypesGlweSecretKey<Precision, OutputKeyDistribution>>::GlweSecretKeyProto,
    );
    type PreExecutionContext = (InputSecretKey, OutputSecretKey);
    type PostExecutionContext = (LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension_in: LweDimension(1024),
                    glwe_dimension_out: GlweDimension(1),
                    polynomial_size: PolynomialSize(512),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(7),
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
        let proto_lwe_secret_key_in =
            <Maker as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::new_lwe_secret_key(
                maker,
                parameters.lwe_dimension_in,
            );
        let proto_glwe_secret_key_out = <Maker as PrototypesGlweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::new_glwe_secret_key(
            maker,
            parameters.glwe_dimension_out,
            parameters.polynomial_size,
        );
        (proto_lwe_secret_key_in, proto_glwe_secret_key_out)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_lwe_secret_key_in, proto_glwe_secret_key_out) = sample_proto;
        let synth_lwe_secret_key_in = maker.synthesize_lwe_secret_key(proto_lwe_secret_key_in);
        let synth_glwe_secret_key_out = maker.synthesize_glwe_secret_key(proto_glwe_secret_key_out);
        (synth_lwe_secret_key_in, synth_glwe_secret_key_out)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (lwe_sk_in, glwe_sk_out) = context;
        let cbs_fpksk = unsafe {
            engine.generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                &lwe_sk_in,
                &glwe_sk_out,
                parameters.base_log,
                parameters.level,
                parameters.noise,
            )
        };
        (cbs_fpksk,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (cbs_fpksk,) = context;
        maker.destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(cbs_fpksk);
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(_criteria: &Self::Criteria, _outputs: &[Self::Outcome]) -> bool {
        // The test to verify the generated key is not yet implemented.
        false
    }
}
