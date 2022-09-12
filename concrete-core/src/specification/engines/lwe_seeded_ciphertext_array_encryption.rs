use super::engine_error;
use crate::prelude::Variance;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweSecretKeyEntity, LweSeededCiphertextArrayEntity, PlaintextArrayEntity,
};

engine_error! {
    LweSeededCiphertextArrayEncryptionError for LweSeededCiphertextArrayEncryptionEngine @
}

/// A trait for engines encrypting seeded LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a seeded LWE ciphertext array
/// containing the element-wise encryption of the `input` plaintext array, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// ## Seeded LWE array encryption
/// ###### inputs:
/// - $\vec{\mathsf{pt}}\in\mathbb{Z}\_q^t$: a plaintext array
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathsf{seed} \in\mathcal{S}$: a public seed
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\mathcal{D}\_{\sigma^2,\mu}$: a normal distribution of variance $\sigma^2$ and mean $\mu$
///
/// ###### outputs:
/// - $\vec{\tilde{\mathsf{ct}}} = \left( \mathsf{seed} , \vec{b}\right) \in
///   \mathsf{SeededLWEArray}^{n, t}\_{\vec{s}, G}(
///  \vec{\mathsf{pt}})\subseteq \mathcal{S}\times \mathbb{Z}\_q^t$: a seeded LWE ciphertext array
///
/// ###### algorithm:
/// 1. let $\vec{b} \in \mathbb{Z}\_q^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(b\_i, \mathsf{pt\_i})$ in $(\vec{b}, \vec{\mathsf{pt}})$
///     - uniformly sample $n$ integers in $\mathbb{Z}\_q$ from $G$ and store them in
/// $\vec{a}\in\mathbb{Z}^n\_q$
///     - sample an integer error term $e \hookleftarrow\mathcal{D}\_{\sigma^2,\mu}$
///     - compute $b\_i = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt\_i} + e
/// \in\mathbb{Z}\_q$
/// 4. output $\left( \mathsf{seed} , \vec{b}\right)$
pub trait LweSeededCiphertextArrayEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: LweSeededCiphertextArrayEntity,
{
    /// Encrypts a seeded LWE ciphertext array.
    fn encrypt_lwe_seeded_ciphertext_array(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> Result<CiphertextArray, LweSeededCiphertextArrayEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a seeded LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextArrayEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_seeded_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> CiphertextArray;
}
