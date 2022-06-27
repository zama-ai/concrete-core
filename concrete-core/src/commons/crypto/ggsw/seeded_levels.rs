use super::super::glwe::GlweBody;
use crate::commons::math::decomposition::DecompositionLevel;
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::random::CompressionSeed;
use crate::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use concrete_commons::parameters::{GlweDimension, GlweSize, PolynomialSize};
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A matrix containing a single level of gadget decomposition.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct GgswSeededLevelMatrix<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    level: DecompositionLevel,
    compression_seed: CompressionSeed,
}

tensor_traits!(GgswSeededLevelMatrix);

impl<Cont> GgswSeededLevelMatrix<Cont> {
    /// Creates a GGSW seeded level matrix from an arbitrary container.
    pub fn from_container(
        cont: Cont,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        level: DecompositionLevel,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => poly_size.0, 2);
        Self {
            tensor,
            poly_size,
            glwe_size,
            level,
            compression_seed,
        }
    }

    /// Returns the size of the GLWE ciphertexts composing the GGSW level matrix.
    ///
    /// This is also the number of columns of the expanded matrix (assuming it is a matrix of
    ///  polynomials), as well as the number of rows of the matrix.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the index of the level corresponding to this matrix.
    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.level
    }

    /// Returns the size of the polynomials of the current ciphertext.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns an iterator over the borrowed rows of the matrix.
    pub fn row_iter(
        &self,
    ) -> impl Iterator<Item = GgswSeededLevelRow<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(2 * self.poly_size.0)
            .enumerate()
            .map(move |(row_idx, sub)| {
                GgswSeededLevelRow::from_container(
                    sub.into_container(),
                    self.poly_size,
                    self.level,
                    self.glwe_size.to_glwe_dimension(),
                    self.compression_seed,
                    row_idx,
                )
            })
    }

    /// Returns an iterator over the mutably borrowed rows of the matrix.
    pub fn row_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GgswSeededLevelRow<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = 2 * self.poly_size.0;
        let poly_size = self.poly_size;
        let glwe_dimension = self.glwe_size.to_glwe_dimension();
        let level = self.level;
        let compression_seed = self.compression_seed;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(row_idx, sub)| {
                GgswSeededLevelRow::from_container(
                    sub.into_container(),
                    poly_size,
                    level,
                    glwe_dimension,
                    compression_seed,
                    row_idx,
                )
            })
    }

    /// Returns a parallel iterator over the mutably borrowed rows of the matrix.
    ///
    /// # Note
    ///
    /// This method uses _rayon_ internally, and is hidden behind the "multithread" feature
    /// gate.
    #[cfg(feature = "__commons_parallel")]
    pub fn par_row_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = GgswSeededLevelRow<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Send + Sync,
    {
        let chunks_size = 2 * self.poly_size.0;
        let poly_size = self.poly_size;
        let glwe_dimension = self.glwe_size.to_glwe_dimension();
        let level = self.level;
        let compression_seed = self.compression_seed;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(row_idx, sub)| {
                GgswSeededLevelRow::from_container(
                    sub.into_container(),
                    poly_size,
                    level,
                    glwe_dimension,
                    compression_seed,
                    row_idx,
                )
            })
    }
}

/// A row of a GGSW level matrix.
pub struct GgswSeededLevelRow<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    level: DecompositionLevel,
    glwe_dimension: GlweDimension,
    compression_seed: CompressionSeed,
    row_index: usize,
}

tensor_traits!(GgswSeededLevelRow);

impl<Cont> GgswSeededLevelRow<Cont> {
    /// Creates an Rgsw seeded level row from an arbitrary container.
    pub fn from_container(
        cont: Cont,
        poly_size: PolynomialSize,
        level: DecompositionLevel,
        glwe_dimension: GlweDimension,
        compression_seed: CompressionSeed,
        row_index: usize,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.as_slice().len() => poly_size.0, 2);
        Self {
            tensor,
            poly_size,
            level,
            glwe_dimension,
            compression_seed,
            row_index,
        }
    }

    /// Returns the size of the glwe ciphertext composing this level row.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_dimension.to_glwe_size()
    }

    /// Returns the index of the level corresponding to this row.
    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.level
    }

    /// Returns the size of the polynomials used in the row.
    pub fn polynomial_size(&self) -> PolynomialSize
    where
        Cont: AsRefSlice,
    {
        self.poly_size
    }

    #[allow(clippy::type_complexity)]
    /// Consumes the row and returns the elements required to recreate a row.
    pub fn get_matrix_poly_coeffs(
        &self,
    ) -> (
        (usize, Polynomial<&[<Cont as AsRefSlice>::Element]>),
        GlweBody<&[<Cont as AsRefSlice>::Element]>,
    )
    where
        Cont: AsRefSlice,
    {
        let (poly_coeff, glwe_body) = self.tensor.as_slice().split_at(self.poly_size.0);
        (
            (
                self.row_index,
                Polynomial::from_tensor(Tensor::from_container(poly_coeff)),
            ),
            GlweBody {
                tensor: Tensor::from_container(glwe_body),
            },
        )
    }

    #[allow(clippy::type_complexity)]
    /// Consumes the row and returns the mutable elements required to recreate a row.
    pub fn get_mut_matrix_poly_coeffs(
        &mut self,
    ) -> (
        (usize, Polynomial<&mut [<Cont as AsMutSlice>::Element]>),
        GlweBody<&mut [<Cont as AsMutSlice>::Element]>,
    )
    where
        Cont: AsMutSlice,
    {
        let (poly_coeff, glwe_body) = self.tensor.as_mut_slice().split_at_mut(self.poly_size.0);
        (
            (
                self.row_index,
                Polynomial::from_tensor(Tensor::from_container(poly_coeff)),
            ),
            GlweBody {
                tensor: Tensor::from_container(glwe_body),
            },
        )
    }
}
