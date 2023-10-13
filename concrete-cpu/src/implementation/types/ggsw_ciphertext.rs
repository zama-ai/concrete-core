use crate::implementation::{Container, ContainerMut, Split};

use super::{
    DecompositionBaseLog, DecompositionLevel, DecompositionLevelCount, GlweDimension,
    PolynomialSize,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[readonly::make]
pub struct GgswLevelRow<C: Container> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,

    pub decomposition_level: DecompositionLevel,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[readonly::make]
pub struct GgswLevelMatrix<C: Container> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,

    pub decomposition_level: DecompositionLevel,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[readonly::make]
pub struct GgswCiphertext<C: Container> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,
    pub decomposition_level_count: DecompositionLevelCount,

    pub decomposition_base_log: DecompositionBaseLog,
}

impl<C: Container> GgswLevelRow<C> {
    pub fn data_len(polynomial_size: PolynomialSize, glwe_dimension: GlweDimension) -> usize {
        polynomial_size.0 * glwe_dimension.as_glwe_size().0
    }

    pub fn new(
        data: C,
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        debug_assert_eq!(data.len(), Self::data_len(polynomial_size, glwe_dimension));
        Self {
            data,
            polynomial_size,
            glwe_dimension,
            decomposition_level,
        }
    }

    pub fn as_view(&self) -> GgswLevelRow<&[C::Item]> {
        GgswLevelRow {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level: self.decomposition_level,
        }
    }

    pub fn as_mut_view(&mut self) -> GgswLevelRow<&mut [C::Item]>
    where
        C: ContainerMut,
    {
        GgswLevelRow {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level: self.decomposition_level,
        }
    }

    pub fn into_data(self) -> C {
        self.data
    }
}

impl<C: Container> GgswLevelMatrix<C> {
    pub fn data_len(polynomial_size: PolynomialSize, glwe_dimension: GlweDimension) -> usize {
        polynomial_size.0 * glwe_dimension.as_glwe_size().0 * glwe_dimension.as_glwe_size().0
    }

    pub fn new(
        data: C,
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        debug_assert_eq!(data.len(), Self::data_len(polynomial_size, glwe_dimension));
        Self {
            data,
            polynomial_size,
            glwe_dimension,
            decomposition_level,
        }
    }

    pub fn as_view(&self) -> GgswLevelMatrix<&[C::Item]> {
        GgswLevelMatrix {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level: self.decomposition_level,
        }
    }

    pub fn as_mut_view(&mut self) -> GgswLevelMatrix<&mut [C::Item]>
    where
        C: ContainerMut,
    {
        GgswLevelMatrix {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level: self.decomposition_level,
        }
    }

    pub fn into_data(self) -> C {
        self.data
    }

    pub fn into_rows_iter(self) -> impl DoubleEndedIterator<Item = GgswLevelRow<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.glwe_dimension.as_glwe_size().0)
            .map(move |slice| {
                GgswLevelRow::new(
                    slice,
                    self.polynomial_size,
                    self.glwe_dimension,
                    self.decomposition_level,
                )
            })
    }
}

impl<C: Container> GgswCiphertext<C> {
    pub fn data_len(
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        decomposition_level_count: DecompositionLevelCount,
    ) -> usize {
        polynomial_size.0
            * glwe_dimension.as_glwe_size().0
            * glwe_dimension.as_glwe_size().0
            * decomposition_level_count.0
    }

    pub fn new(
        data: C,
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self {
        debug_assert_eq!(
            data.len(),
            Self::data_len(polynomial_size, glwe_dimension, decomposition_level_count)
        );
        Self {
            data,
            polynomial_size,
            glwe_dimension,
            decomposition_level_count,
            decomposition_base_log,
        }
    }

    pub fn as_view(&self) -> GgswCiphertext<&[C::Item]> {
        GgswCiphertext {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> GgswCiphertext<&mut [C::Item]>
    where
        C: ContainerMut,
    {
        GgswCiphertext {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn into_data(self) -> C {
        self.data
    }

    pub fn into_level_matrices_iter(self) -> impl DoubleEndedIterator<Item = GgswLevelMatrix<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.decomposition_level_count.0)
            .enumerate()
            .map(move |(i, slice)| {
                GgswLevelMatrix::new(
                    slice,
                    self.polynomial_size,
                    self.glwe_dimension,
                    DecompositionLevel(i + 1),
                )
            })
    }
}
