pub use crate::generation::prototypes::{
    LwePrivateFunctionalPackingKeyswitchKeyPrototype,
    ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey32,
    ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::PrototypesCleartextArray;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::StandardDev;

use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount,
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine,
};

use super::PrototypesGlweSecretKey;

/// A trait allowing to manipulate private functional packing keyswitch key prototypes.
pub trait PrototypesLwePrivateFunctionalPackingKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
    + PrototypesCleartextArray<Precision>
{
    type LwePrivateFunctionalPackingKeyswitchKeyProto: LwePrivateFunctionalPackingKeyswitchKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    #[allow(clippy::too_many_arguments)]
    fn new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<
            Precision,
            InputKeyDistribution,
        >>::LweSecretKeyProto,
        output_key: &<Self as PrototypesGlweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(Precision::Raw) -> Precision::Raw,
        polynomial: &<Self as PrototypesCleartextArray<Precision>>::CleartextArrayProto,
    ) -> Self::LwePrivateFunctionalPackingKeyswitchKeyProto;
}

impl
    PrototypesLwePrivateFunctionalPackingKeyswitchKey<
        Precision32,
        BinaryKeyDistribution,
        BinaryKeyDistribution,
    > for Maker
{
    type LwePrivateFunctionalPackingKeyswitchKeyProto =
        ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey32;

    fn new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u32) -> u32,
        polynomial_scalar: &Self::CleartextArrayProto,
    ) -> Self::LwePrivateFunctionalPackingKeyswitchKeyProto {
        ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey32(
            self.default_engine
                .generate_new_lwe_private_functional_packing_keyswitch_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_level,
                    decomposition_base_log,
                    noise,
                    f,
                    &polynomial_scalar.0,
                )
                .unwrap(),
        )
    }
}

impl
    PrototypesLwePrivateFunctionalPackingKeyswitchKey<
        Precision64,
        BinaryKeyDistribution,
        BinaryKeyDistribution,
    > for Maker
{
    type LwePrivateFunctionalPackingKeyswitchKeyProto =
        ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey64;

    fn new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u64) -> u64,
        polynomial_scalar: &Self::CleartextArrayProto,
    ) -> Self::LwePrivateFunctionalPackingKeyswitchKeyProto {
        ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey64(
            self.default_engine
                .generate_new_lwe_private_functional_packing_keyswitch_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_level,
                    decomposition_base_log,
                    noise,
                    f,
                    &polynomial_scalar.0,
                )
                .unwrap(),
        )
    }
}
