// use super::engine_error;
// use crate::specification::engines::AbstractEngine;
//
// use crate::backends::core::private::crypto::circuit_bootstrap::DeltaLog;
// use crate::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
// use crate::prelude::{GgswCiphertextEntity, PackingKeyswitchKeyEntity};
// use crate::specification::entities::{
//     GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
// };
// use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
//
// engine_error! {
//     LweCiphertextDiscardingBootstrapError for LweCiphertextDiscardingBootstrapEngine @
//     InputLweDimensionMismatch => "The input ciphertext and key LWE dimension must be the same.",
//     OutputLweDimensionMismatch => "The output ciphertext dimension and key size (dimension * \
//                                    polynomial size) must be the same.",
//     AccumulatorPolynomialSizeMismatch => "The accumulator and key polynomial sizes must be the
// same.",     AccumulatorGlweDimensionMismatch => "The accumulator and key GLWE dimensions must be
// the same." }
//
// /// Unsafely bootstrap an LWE ciphertext .
// ///
// /// # Safety
// /// For the _general_ safety concerns regarding this operation, refer to the different variants
// /// of [`LweCiphertextDiscardingCircuitBootstrapError`]. For safety concerns _specific_ to an
// /// engine,
// /// refer to the implementer safety section.
// /// # Formal Definition
// pub trait LweCiphertextDiscardingCircuitBootstrapEngine<
//     BootstrapKey,
//     InputCiphertext,
//     OutputCiphertext,
//     VectorFunctionalPackingKeyswitchKey,
//     Level,
//     Base,
//     Delta,
// >: AbstractEngine where
//     BootstrapKey: LweBootstrapKeyEntity,
//     InputCiphertext: LweCiphertextEntity<KeyDistribution = BootstrapKey::InputKeyDistribution>,
//     OutputCiphertext: GgswCiphertextEntity,
//     VectorFunctionalPackingKeyswitchKey: Vec<PackingKeyswitchKeyEntity>,
//     Level,
//     Base,
//     Delta,
// {
//     /// Bootstrap an LWE ciphertext .
//     fn discard_circuit_bootstrap_lwe_ciphertext_unchecked(
//         &mut self,
//         output: &mut OutputCiphertext,
//         input: &InputCiphertext,
//         bsk: &BootstrapKey,
//         vec_pkks: &Vec<FunctionalPackingKeyswitchKey<Vec<u64>>>,
//         level: DecompositionLevelCount,
//         base: DecompositionBaseLog,
//         delta: DeltaLog,
//     );
// }
