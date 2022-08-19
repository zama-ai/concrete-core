pub use crate::generation::prototypes::{
    PrivateFunctionalPackingKeyswitchKeyPrototype,
    ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32,
    ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::PrototypesCleartextVector;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_commons::dispersion::StandardDev;

use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use concrete_core::prelude::PrivateFunctionalPackingKeyswitchKeyCreationEngine;

use super::PrototypesGlweSecretKey;

/// A trait allowing to manipulate private functional packing keyswitch key prototypes.
pub trait PrototypesPrivateFunctionalPackingKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
    + PrototypesCleartextVector<Precision>
{
    type PrivateFunctionalPackingKeyswitchKeyProto: PrivateFunctionalPackingKeyswitchKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    #[allow(clippy::too_many_arguments)]
    fn new_private_functional_packing_keyswitch_key(
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
        polynomial: &<Self as PrototypesCleartextVector<Precision>>::CleartextVectorProto,
    ) -> Self::PrivateFunctionalPackingKeyswitchKeyProto;
}

impl
    PrototypesPrivateFunctionalPackingKeyswitchKey<
        Precision32,
        BinaryKeyDistribution,
        BinaryKeyDistribution,
    > for Maker
{
    type PrivateFunctionalPackingKeyswitchKeyProto =
        ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32;

    fn new_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u32) -> u32,
        polynomial_scalar: &Self::CleartextVectorProto,
    ) -> Self::PrivateFunctionalPackingKeyswitchKeyProto {
        ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32(
            self.default_engine
                .create_private_functional_packing_keyswitch_key(
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
    PrototypesPrivateFunctionalPackingKeyswitchKey<
        Precision64,
        BinaryKeyDistribution,
        BinaryKeyDistribution,
    > for Maker
{
    type PrivateFunctionalPackingKeyswitchKeyProto =
        ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64;

    fn new_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u64) -> u64,
        polynomial_scalar: &Self::CleartextVectorProto,
    ) -> Self::PrivateFunctionalPackingKeyswitchKeyProto {
        ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64(
            self.default_engine
                .create_private_functional_packing_keyswitch_key(
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
