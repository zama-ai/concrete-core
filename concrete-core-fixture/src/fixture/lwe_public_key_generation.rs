use crate::fixture::Fixture;
use crate::generation::prototyping::PrototypesLweSecretKey;
use crate::generation::synthesizing::{SynthesizesLwePublicKey, SynthesizesLweSecretKey};
use crate::generation::{IntegerPrecision, KeyDistributionMarker, Maker};
use concrete_core::prelude::{
    LweDimension, LwePublicKeyEntity, LwePublicKeyGenerationEngine,
    LwePublicKeyZeroEncryptionCount, LweSecretKeyEntity, Variance,
};

/// A fixture for the types implementing the `LwePublicKeyGenerationEngine` trait.
pub struct LwePublicKeyGenerationFixture;

#[derive(Debug)]
pub struct LwePublicKeyGenerationParameters {
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LwePublicKeyZeroEncryptionCount,
    pub noise: Variance,
}

impl<Precision, KeyDistribution, Engine, SecretKey, PublicKey>
    Fixture<Precision, (KeyDistribution,), Engine, (SecretKey, PublicKey)>
    for LwePublicKeyGenerationFixture
where
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    Engine: LwePublicKeyGenerationEngine<SecretKey, PublicKey>,
    SecretKey: LweSecretKeyEntity,
    PublicKey: LwePublicKeyEntity,
    Maker: SynthesizesLweSecretKey<Precision, KeyDistribution, SecretKey>
        + SynthesizesLwePublicKey<Precision, KeyDistribution, PublicKey>,
{
    type Parameters = LwePublicKeyGenerationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes =
        (<Maker as PrototypesLweSecretKey<Precision, KeyDistribution>>::LweSecretKeyProto,);
    type PreExecutionContext = (SecretKey,);
    type PostExecutionContext = (SecretKey, PublicKey);
    type Criteria = ();
    type Outcome = ();

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![LwePublicKeyGenerationParameters {
                lwe_dimension: LweDimension(630),
                lwe_ciphertext_count: LwePublicKeyZeroEncryptionCount(10),
                noise: Variance(0.00000001),
            }]
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
        (maker.new_lwe_secret_key(parameters.lwe_dimension),)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_secret_key,) = sample_proto;
        let synth_secret_key = maker.synthesize_lwe_secret_key(proto_secret_key);
        (synth_secret_key,)
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (secret_key,) = context;
        let public_key = unsafe {
            engine.generate_new_lwe_public_key_unchecked(
                &secret_key,
                parameters.noise,
                parameters.lwe_ciphertext_count,
            )
        };
        (secret_key, public_key)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (sk, pk) = context;
        maker.destroy_lwe_secret_key(sk);
        maker.destroy_lwe_public_key(pk);
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
    }

    fn verify(
        _parameters: &Self::Parameters,
        _criteria: &Self::Criteria,
        _outputs: &[Self::Outcome],
    ) -> bool {
        // The test to verify the generated key is not yet implemented.
        false
    }
}
