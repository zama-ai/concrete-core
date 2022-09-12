use super::engine_error;
use crate::prelude::AbstractEngine;

use crate::specification::entities::{GlweCiphertextArrayEntity, GlweSeededCiphertextArrayEntity};

engine_error! {
    GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationError
    for GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine @
}

/// A trait for engines transforming GLWE seeded ciphertexts arrays into GLWE ciphertexts arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing GLWE seeded ciphertext
/// array into a GLWE ciphertext array.
///
/// # Formal Definition
///
/// ## GLWE seeded ciphertext array to GLWE ciphertext array transformation
/// ###### inputs:
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\vec{\tilde{\mathsf{CT}}} = \left( \mathsf{seed} , \vec{\tilde{B}} \right) \in
///   \mathsf{SeededGLWEArray}^{k,t}\_{\vec{S}, G}( \vec{\mathsf{PT}} )\subseteq \mathcal{S}\times
///   \mathcal{R}\_q^t$: a seeded GLWE ciphertext array
///
/// ###### outputs:
/// - $\vec{\mathsf{CT}} = \vec{\left( \vec{A} , B \right)} \in \mathsf{GLWEArray}^{k,t}\_{\vec{S}}
///   (\vec{\mathsf{PT}} )\subseteq {\mathcal{R}\_q^{k+1}}^t$: a GLWE ciphertext array
///
/// ###### algorithm:
/// 1. let $\vec{\mathsf{CT}} = \vec{\left( \vec{A} , B \right)} \in
/// \mathsf{GLWEArray}^{k,t}\_{\vec{S}} (\vec{\mathsf{PT}} )\subseteq {\mathcal{R}\_q^{k+1}}^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(\left( \vec{A\_i}, B\_i\right) , \tilde{B\_i})$ in $(\vec{\left( \vec{A} ,
/// B\right)}, \vec{\tilde{B}})$
///     - uniformly sample each coefficient of the polynomial array $\vec{A\_i}\in\mathcal{R}^k\_q$
///       from $G$
///     - set $B\_i = \tilde{B\_i}$
/// 4. output $\vec{\left( \vec{A} , B\right)}$
pub trait GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine<
    InputCiphertextArray,
    OutputCiphertextArray,
>: AbstractEngine where
    InputCiphertextArray: GlweSeededCiphertextArrayEntity,
    OutputCiphertextArray: GlweCiphertextArrayEntity,
{
    /// Does the transformation of the GLWE seeded ciphertext array into a GLWE ciphertext array
    fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
        &mut self,
        glwe_seeded_ciphertext_array: InputCiphertextArray,
    ) -> Result<
        OutputCiphertextArray,
        GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms a GLWE seeded ciphertext array into a GLWE ciphertext array
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array_unchecked(
        &mut self,
        glwe_seeded_ciphertext_array: InputCiphertextArray,
    ) -> OutputCiphertextArray;
}
