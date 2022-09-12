use super::super::math::polynomial::*;
use super::super::{Container, IntoChunks};
use crate::commons::math::torus::UnsignedTorus;
use crate::prelude::{GlweSize, PolynomialSize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "backend_fft_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct GlweCiphertext<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
}

pub type GlweCiphertextView<'a, Scalar> = GlweCiphertext<&'a [Scalar]>;
pub type GlweCiphertextMutView<'a, Scalar> = GlweCiphertext<&'a mut [Scalar]>;

impl<C: Container> GlweCiphertext<C> {
    pub fn new(data: C, polynomial_size: PolynomialSize, glwe_size: GlweSize) -> Self
    where
        C: Container,
    {
        assert_eq!(data.container_len(), polynomial_size.0 * glwe_size.0);

        Self {
            data,
            polynomial_size,
            glwe_size,
        }
    }

    /// Returns an iterator over the polynomials in `self`.
    pub fn into_polynomials(self) -> impl DoubleEndedIterator<Item = Polynomial<C>>
    where
        C: IntoChunks,
    {
        self.data
            .split_into(self.glwe_size.0)
            .map(|chunk| Polynomial { data: chunk })
    }

    pub fn data(self) -> C {
        self.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn as_view(&self) -> GlweCiphertextView<'_, C::Element> {
        GlweCiphertext {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
        }
    }

    pub fn as_mut_view(&mut self) -> GlweCiphertextMutView<'_, C::Element>
    where
        C: AsMut<[C::Element]>,
    {
        GlweCiphertext {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
        }
    }
}

impl<'a, Scalar> GlweCiphertextView<'a, Scalar> {
    /// Fills an LWE ciphertext with the extraction of one coefficient of the current GLWE
    /// ciphertext.
    pub fn fill_lwe_with_sample_extraction(self, lwe: &mut [Scalar], nth: usize)
    where
        Scalar: UnsignedTorus,
    {
        let (lwe_body, lwe_mask) = lwe.split_last_mut().unwrap();
        let (glwe_mask, glwe_body) = self
            .data
            .split_at(self.polynomial_size.0 * (self.glwe_size.0 - 1));

        // We copy the body
        *lwe_body = glwe_body[nth];

        // We copy the mask (each polynomial is in the wrong order)
        lwe_mask.copy_from_slice(glwe_mask);

        // We compute the number of elements which must be
        // turned into their opposite
        let opposite_count = self.polynomial_size.0 - nth - 1;
        for lwe_mask_poly in lwe_mask.into_chunks(self.polynomial_size.0) {
            lwe_mask_poly.reverse();
            for x in &mut lwe_mask_poly[0..opposite_count] {
                *x = x.wrapping_neg();
            }
            lwe_mask_poly.rotate_left(opposite_count);
        }
    }
}
