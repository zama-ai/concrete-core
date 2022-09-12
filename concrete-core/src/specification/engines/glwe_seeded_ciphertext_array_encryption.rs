use super::engine_error;
use crate::prelude::Variance;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweSecretKeyEntity, GlweSeededCiphertextArrayEntity, PlaintextArrayEntity,
};

engine_error! {
    GlweSeededCiphertextArrayEncryptionError for GlweSeededCiphertextArrayEncryptionEngine @
    PlaintextCountMismatch => "The key polynomial size must divide the plaintext count of the input \
                               array."
}

impl<EngineError: std::error::Error> GlweSeededCiphertextArrayEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextArray>(
        key: &SecretKey,
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextArray: PlaintextArrayEntity,
    {
        if (input.plaintext_count().0 % key.polynomial_size().0) != 0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting GLWE seeded ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE seeded ciphertext array
/// containing the piece-wise encryptions of the `input` plaintext array, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// ## Seeded GLWE array encryption
/// ###### inputs:
/// - $\vec{\mathsf{PT}}\in\mathcal{R}\_q^t$: a plaintext array
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
/// - $\mathsf{seed} \in\mathcal{S}$: a public seed
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\mathcal{D}\_{\sigma^2,\mu}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\vec{\tilde{\mathsf{CT}}} = \left( \mathsf{seed} , \vec{\tilde{B}} \right) \in
///   \mathsf{SeededGLWEArray}^{k,t}\_{\vec{S}, G}( \vec{\mathsf{PT}} )\subseteq \mathcal{S}\times
///   \mathcal{R}\_q^t$: a seeded GLWE ciphertext array
///
/// ###### algorithm:
/// 1. let $\vec{B} \in \mathcal{R}\_q^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(B\_i, \mathsf{PT\_i})$ in $(\vec{B}, \vec{\mathsf{PT}})$
///     - uniformly sample each coefficient of the polynomial array $\vec{A}\in\mathcal{R}^k\_q$
///       from $G$
///     - sample each integer error coefficient of an error polynomial $E\in\mathcal{R}\_q$ from
///       $\mathcal{D\_{\sigma^2,\mu}}$
///     - compute $B\_i = \left\langle \vec{A} , \vec{S} \right\rangle + \mathsf{PT} + E
/// \in\mathcal{R}\_q$
/// 4. output $\left( \mathsf{seed} , \vec{B}\right)$
pub trait GlweSeededCiphertextArrayEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: GlweSeededCiphertextArrayEntity,
{
    /// Encrypts a GLWE seeded ciphertext array.
    fn encrypt_glwe_seeded_ciphertext_array(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> Result<CiphertextArray, GlweSeededCiphertextArrayEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE seeded ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextArrayEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_glwe_seeded_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> CiphertextArray;
}
