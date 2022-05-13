// use crate::backends::core::implementation::engines::CoreEngine;
// use crate::backends::core::implementation::entities::{
//     FourierLweBootstrapKey32, FourierLweBootstrapKey64, GlweCiphertext32, GlweCiphertext64,
//     LweCiphertext32, LweCiphertext64,
// };
// use crate::backends::core::private::crypto::circuit_bootstrap::{circuit_bootstrap, DeltaLog};
// use crate::backends::core::private::crypto::glwe::FunctionalPackingKeyswitchKey;
// use crate::backends::core::private::math::decomposition::DecompositionLevel;
// use crate::backends::core::private::math::fft::ALLOWED_POLY_SIZE;
// use crate::prelude::{
//     CoreError, DecompositionBaseLog, GgswCiphertext64, GlweCiphertextEntity, LweBootstrapKeyEntity,
// };
// use crate::specification::engines::LweCiphertextDiscardingCircuitBootstrapEngine;
// use concrete_commons::parameters::DecompositionLevelCount;
//
// //TODO: Manage error
// // impl From<CoreError> for LweCiphertextDiscardingCircuitBootstrapEngine<CoreError> {
// //     fn from(err: CoreError) -> Self {
// //         Self::Engine(err)
// //     }
// // }
//
// //TODO: 32 bit version
//
// /// # Description:
// /// Implementation of [`LweCiphertextDiscardingCircuitBootstrapEngine`] for [`CoreEngine`] that operates on
// /// 64 bits integers.
// impl
//     LweCiphertextDiscardingCircuitBootstrapEngine<
//         GgswCiphertext64,
//         &LweCiphertext64,
//         &FourierLweBootstrapKey64,
//         &Vec<FunctionalPackingKeyswitchKey<Vec<u64>>>,
//         DecompositionLevelCount,
//         DecompositionBaseLog,
//         DeltaLog,
//     > for CoreEngine
// {
//     //TODO: doc test
//     fn discard_circuit_bootstrap_lwe_ciphertext_unchecked(
//         &mut self,
//         mut output: &mut GgswCiphertext64,
//         input: &LweCiphertext64,
//         bsk: &FourierLweBootstrapKey64,
//         vec_pkks: &Vec<FunctionalPackingKeyswitchKey<Vec<u64>>>,
//         level: DecompositionLevelCount,
//         base: DecompositionBaseLog,
//         delta: DeltaLog,
//     ) {
//         let buffers =
//             self.get_fourier_u64_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
//         let mut out = circuit_bootstrap(bsk, input, buffers, level, base, delta, |x| x, vec_pkks);
//         output = &mut GgswCiphertext64(out);
//     }
//
//     //TODO manage error...
// }
