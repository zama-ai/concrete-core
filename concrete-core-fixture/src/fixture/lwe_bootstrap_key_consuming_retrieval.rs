use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesContainer, PrototypesLweBootstrapKey};
use crate::generation::synthesizing::{SynthesizesContainer, SynthesizesLweBootstrapKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
};

use concrete_core::prelude::{LweBootstrapKeyConsumingRetrievalEngine, LweBootstrapKeyEntity};

#[derive(Debug)]
pub struct LweBootstrapKeyConsumingRetrievalParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
}

/// A fixture for the types implementing the `LweBootstrapKeyConsumingRetrievalEngine` trait with
/// LWE bootstrap key.
pub struct LweBootstrapKeyConsumingRetrievalFixture;

impl<
        Precision,
        InputKeyDistribution,
        OutputKeyDistribution,
        Engine,
        LweBootstrapKey,
        Container,
    >
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (LweBootstrapKey, Container),
    > for LweBootstrapKeyConsumingRetrievalFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKey, Container>,
    LweBootstrapKey: LweBootstrapKeyEntity,
    Maker: SynthesizesLweBootstrapKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            LweBootstrapKey,
        > + SynthesizesContainer<Precision, Container>,
{
    type Parameters = LweBootstrapKeyConsumingRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (
        <Maker as PrototypesLweBootstrapKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
        >>::LweBootstrapKeyProto,
    );
    type PreExecutionContext = (LweBootstrapKey,);
    type PostExecutionContext = (Container,);
    type Criteria = ();
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweBootstrapKeyConsumingRetrievalParameters {
                    lwe_dimension: LweDimension(10),
                    glwe_size: GlweSize(2),
                    polynomial_size: PolynomialSize(256),
                    level: DecompositionLevelCount(2),
                    base_log: DecompositionBaseLog(1),
                },
                LweBootstrapKeyConsumingRetrievalParameters {
                    lwe_dimension: LweDimension(10),
                    glwe_size: GlweSize(3),
                    polynomial_size: PolynomialSize(256),
                    level: DecompositionLevelCount(3),
                    base_log: DecompositionBaseLog(2),
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
        let num_elements = parameters.lwe_dimension.0
            * parameters.level.0
            * parameters.glwe_size.0
            * parameters.glwe_size.0
            * parameters.polynomial_size.0;
        let bsk_proto = maker.transform_raw_vec_to_lwe_bootstrap_key(
            &Precision::Raw::uniform_vec(num_elements),
            parameters.glwe_size,
            parameters.polynomial_size,
            parameters.level,
            parameters.base_log,
        );
        (bsk_proto,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_bsk,) = sample_proto;
        (maker.synthesize_lwe_bootstrap_key(proto_bsk),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (bsk,) = context;
        let raw_bsk = unsafe { engine.consume_retrieve_lwe_bootstrap_key_unchecked(bsk) };
        (raw_bsk,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_bsk,) = sample_proto;
        let (raw_bsk,) = context;
        let proto_container = maker.unsynthesize_container(raw_bsk);
        (
            maker.transform_lwe_bootstrap_key_to_raw_vec(proto_bsk),
            maker.transform_container_to_raw_vec(&proto_container),
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(_criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        means == actual
    }
}
