use crate::implementation::{Container, ContainerMut};

use super::{GlweDimension, PolynomialSize};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[readonly::make]
pub struct GlweCiphertext<C: Container<Item = u64>> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,
}

impl<C: Container<Item = u64>> GlweCiphertext<C> {
    pub fn data_len(polynomial_size: PolynomialSize, glwe_dimension: GlweDimension) -> usize {
        polynomial_size.0 * glwe_dimension.as_glwe_size().0
    }

    pub fn new(data: C, polynomial_size: PolynomialSize, glwe_dimension: GlweDimension) -> Self {
        debug_assert_eq!(data.len(), Self::data_len(polynomial_size, glwe_dimension));
        Self {
            data,
            polynomial_size,
            glwe_dimension,
        }
    }

    pub fn as_view(&self) -> GlweCiphertext<&[u64]> {
        GlweCiphertext {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
        }
    }

    pub fn as_mut_view(&mut self) -> GlweCiphertext<&mut [u64]>
    where
        C: ContainerMut,
    {
        GlweCiphertext {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
        }
    }

    pub fn into_data(self) -> C {
        self.data
    }
}
