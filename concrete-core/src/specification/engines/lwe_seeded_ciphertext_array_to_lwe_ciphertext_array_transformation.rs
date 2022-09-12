use super::engine_error;
use crate::prelude::AbstractEngine;

use crate::specification::entities::{LweCiphertextArrayEntity, LweSeededCiphertextArrayEntity};

engine_error! {
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationError
    for LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine @
}

/// A trait for engines transforming LWE seeded ciphertext arrays into LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing LWE seeded ciphertext array
/// into an LWE ciphertext array.
///
/// # Formal Definition
///
/// ## LWE seeded ciphertext array to LWE ciphertext array transformation
/// ###### inputs:
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\vec{\tilde{\mathsf{ct}}} = \left( \mathsf{seed} , \vec{\tilde{b}}\right) \in
///   \mathsf{SeededLWEArray}^{n, t}\_{\vec{s}, G}( \vec{\mathsf{pt}})\subseteq \mathcal{S}\times
///   \mathbb{Z}\_q^t$: a seeded LWE ciphertext array
///
/// ###### outputs:
/// - $\vec{\mathsf{ct}} = \vec{\left( \vec{a} , b\right)} \in \mathsf{LWEArray}^{n,t}\_{\vec{s}}(
///   \mathsf{pt} )\subseteq {\mathbb{Z}\_q^{(n+1)}}^t$: an LWE ciphertext array
///
/// ###### algorithm:
/// 1. let $\vec{\mathsf{ct}} = \vec{\left( \vec{a} , b\right)} \in
/// \mathsf{LWEArray}^{n,t}\_{\vec{s}}(   \mathsf{pt} )\subseteq {\mathbb{Z}\_q^{(n+1)}}^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(\left(\vec{a\_i}, b\_i\right), \tilde{b\_i})$ in $(\vec{\left( \vec{a} ,
/// b\right)}, \vec{\tilde{b}})$
///     - uniformly sample $n$ integers in $\mathbb{Z}\_q$ from $G$ and store them in
///       $\vec{a}\_i\in\mathbb{Z}^n\_q$
///     - set $b\_i = \tilde{b\_i}$
/// 4. output $\vec{\left( \vec{a} , b\right)}$
pub trait LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine<
    InputCiphertextArray,
    OutputCiphertextArray,
>: AbstractEngine where
    InputCiphertextArray: LweSeededCiphertextArrayEntity,
    OutputCiphertextArray: LweCiphertextArrayEntity,
{
    /// Does the transformation of the LWE seeded ciphertext array into an LWE ciphertext array
    fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
        &mut self,
        lwe_seeded_ciphertext_array: InputCiphertextArray,
    ) -> Result<
        OutputCiphertextArray,
        LweSeededCiphertextArrayToLweCiphertextArrayTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms an LWE seeded ciphertext array into an LWE ciphertext array
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextArrayToLweCiphertextArrayTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array_unchecked(
        &mut self,
        lwe_seeded_ciphertext_array: InputCiphertextArray,
    ) -> OutputCiphertextArray;
}
