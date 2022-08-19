use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesContainer, PrototypesLweBootstrapKey};
use crate::generation::synthesizing::{SynthesizesContainer, SynthesizesLweBootstrapKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
};
use concrete_core::prelude::{LweBootstrapKeyConstructionEngine, LweBootstrapKeyEntity};

/// A fixture for the types implementing the `LweBootstrapKeyConstructionEngine` trait.
pub struct LweBootstrapKeyConstructionFixture;

#[derive(Debug)]
pub struct LweBootstrapKeyConstructionParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub level: DecompositionLevelCount,
    pub base_log: DecompositionBaseLog,
}

impl<Precision, InputKeyDistribution, OutputKeyDistribution, Engine, Container, BootstrapKey>
    Fixture<
        Precision,
        (InputKeyDistribution, OutputKeyDistribution),
        Engine,
        (Container, BootstrapKey),
    > for LweBootstrapKeyConstructionFixture
where
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    Engine: LweBootstrapKeyConstructionEngine<Container, BootstrapKey>,
    BootstrapKey: LweBootstrapKeyEntity,
    Maker: SynthesizesLweBootstrapKey<
            Precision,
            InputKeyDistribution,
            OutputKeyDistribution,
            BootstrapKey,
        > + SynthesizesContainer<Precision, Container>,
{
    type Parameters = LweBootstrapKeyConstructionParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (<Maker as PrototypesContainer<Precision>>::ContainerProto,);
    type PreExecutionContext = (Container,);
    type PostExecutionContext = (BootstrapKey,);
    type Criteria = ();
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            // These parameters are not realistic but as we are just testing container copy/move
            // we would just multiply the amount of data for no real benefit
            vec![
                LweBootstrapKeyConstructionParameters {
                    lwe_dimension: LweDimension(10),
                    glwe_size: GlweSize(2),
                    polynomial_size: PolynomialSize(256),
                    level: DecompositionLevelCount(2),
                    base_log: DecompositionBaseLog(1),
                },
                LweBootstrapKeyConstructionParameters {
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
        (maker.transform_raw_vec_to_container(&Precision::Raw::uniform_vec(num_elements)),)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        (maker.synthesize_container(&sample_proto.0),)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (underlying_container,) = context;
        let lwe_bootstrap_key = unsafe {
            engine.construct_lwe_bootstrap_key_unchecked(
                underlying_container,
                parameters.glwe_size,
                parameters.polynomial_size,
                parameters.base_log,
                parameters.level,
            )
        };
        (lwe_bootstrap_key,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (lwe_bootstrap_key,) = context;
        let bsk_proto = maker.unsynthesize_lwe_bootstrap_key(lwe_bootstrap_key);
        (
            maker.transform_container_to_raw_vec(&sample_proto.0),
            maker.transform_lwe_bootstrap_key_to_raw_vec(&bsk_proto),
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(_criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        // The test to verify the generated key is not yet implemented.
        let (sample, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        sample == actual
    }
}
