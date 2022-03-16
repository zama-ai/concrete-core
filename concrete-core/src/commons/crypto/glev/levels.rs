use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::math::decomposition::DecompositionLevel;
use crate::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use concrete_commons::parameters::{GlweSize, PolynomialSize};
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;
use crate::prelude::GlevCount;

/// A matrix corresponding to a single level of decomposition `l` of a vector of Glevs.
/// It contains `glev_count` GLWE ciphertexts of size `glwe_size` and polynomial size `poly_size`.
/// Each row of the matrix corresponds to a GLWE ciphertext.
pub struct GlevListLevelMatrix<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    glev_count: GlevCount,
    level: DecompositionLevel,
}

tensor_traits!(GlevListLevelMatrix);

impl<Cont> GlevListLevelMatrix<Cont> {
    /// Creates a Glev list level matrix from an arbitrary container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::prelude::GlevCount;
    /// let level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(level_matrix.glwe_size(), GlweSize(7));
    /// assert_eq!(level_matrix.glev_count(), GlevCount(7));
    /// assert_eq!(level_matrix.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn from_container(
        cont: Cont,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        glev_count: GlevCount,
        level: DecompositionLevel,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => glwe_size.0, poly_size.0, glev_count.0);
        GlevListLevelMatrix {
            tensor,
            poly_size,
            glwe_size,
            glev_count,
            level,
        }
    }

    /// Returns the size of the GLWE ciphertexts composing the Glev list level matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::prelude::GlevCount;
    /// let level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of Glev in the list
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::prelude::GlevCount;
    /// let level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.glwe_size(), GlweSize(7));
    /// ```
    pub fn glev_count(&self) -> GlevCount {
        self.glev_count
    }

    /// Returns the index of the level corresponding to this matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::prelude::GlevCount;
    /// let level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.level
    }

    /// Returns the size of the polynomials of the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::prelude::GlevCount;
    /// let level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns an iterator over the borrowed rows (GLWE's) of the matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::prelude::GlevCount;
    /// let level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// for row in level_matrix.row_iter() {
    ///     assert_eq!(row.glwe_size(), GlweSize(7));
    ///     assert_eq!(row.polynomial_size(), PolynomialSize(10));
    /// }
    /// assert_eq!(level_matrix.row_iter().count(), 7);
    /// ```
    pub fn row_iter(&self) -> impl Iterator<Item = GlevListLevelRow<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.poly_size.0 * self.glwe_size.0)
            .map(move |tens| {
                GlevListLevelRow::from_container(tens.into_container(), self.poly_size, self.level)
            })
    }

    pub fn nth_row_iter(&self, index: usize) -> impl Iterator<Item = GlweCiphertext<&[<Self as 
    AsRefTensor>::Element]>>
        where
            Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.poly_size.0 * self.glwe_size.0)
            .nth(index)
            .map(move |tens| {
                GlweCiphertext::from_container(tens.into_container(), self.poly_size)
            })
    }
    
    /// Returns an iterator over the mutably borrowed rows of the matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::GlevCount;
    /// let mut level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// for mut row in level_matrix.row_iter_mut() {
    ///     row.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert!(level_matrix.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(level_matrix.row_iter_mut().count(), 7);
    /// ```
    pub fn row_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GlevListLevelRow<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let level = self.level;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |tens| GlevListLevelRow::from_container(tens.into_container(), poly_size, level))
    }

    /// Returns a parallel iterator over the mutably borrowed rows of the matrix.
    ///
    /// # Note
    ///
    /// This method uses _rayon_ internally, and is hidden behind the "__commons_parallel" feature
    /// gate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use rayon::iter::ParallelIterator;
    /// use concrete_core::commons::crypto::glev::GlevListLevelMatrix;
    /// use concrete_core::prelude::GlevCount;
    /// let mut level_matrix = GlevListLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     GlevCount(7),
    ///     DecompositionLevel(1),
    /// );
    /// level_matrix.par_row_iter_mut().for_each(|mut row| {
    ///     row.as_mut_tensor().fill_with_element(9);
    /// });
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_row_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = GlevListLevelRow<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Send + Sync,
    {
        let chunks_size = self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let level = self.level;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .map(move |tens| GlevListLevelRow::from_container(tens.into_container(), poly_size, level))
    }
}

/// A row of a Glev list level matrix (each rwo is a GLWE ciphertext).
pub struct GlevListLevelRow<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    level: DecompositionLevel,
}

tensor_traits!(GlevListLevelRow);

impl<Cont> GlevListLevelRow<Cont> {
    /// Creates a Glev list level row from an arbitrary container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(level_row.glwe_size(), GlweSize(7));
    /// assert_eq!(level_row.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn from_container(cont: Cont, poly_size: PolynomialSize, level: DecompositionLevel) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => poly_size.0);
        GlevListLevelRow {
            tensor,
            poly_size,
            level,
        }
    }

    /// Returns the size of the glwe ciphertext composing this level row.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.poly_size.0);
        GlweSize(self.as_tensor().len() / self.poly_size.0)
    }

    /// Returns the index of the level corresponding to this row.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::PolynomialSize;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.level
    }

    /// Returns the size of the polynomials used in the row.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::PolynomialSize;
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Consumes the row and returns its container wrapped into an `GlweCiphertext`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::parameters::{GlweSize, PolynomialSize};
    /// use concrete_core::commons::math::decomposition::DecompositionLevel;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// let glwe = level_row.into_glwe();
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(glwe.size(), GlweSize(7));
    /// ```
    pub fn into_glwe(self) -> GlweCiphertext<Cont> {
        GlweCiphertext {
            tensor: self.tensor,
            poly_size: self.poly_size,
        }
    }
}
