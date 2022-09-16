use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::backends::ntt::private::math::polynomial::NttPolynomial;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::math::tensor::{
    ck_dim_div, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use std::fmt::Debug;

use crate::backends::ntt::private::math::transform::Ntt;
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use crate::prelude::{GlweSize, PolynomialSize};

/// A GLWE ciphertext in the NTT Domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttGlweCiphertext<Cont> {
    tensor: Tensor<Cont>,
    pub poly_size: PolynomialSize,
    pub glwe_size: GlweSize,
}

impl<NttScalar: UnsignedInteger> NttGlweCiphertext<Vec<ModQ<NttScalar>>> {
    /// Allocates a new GLWE ciphertext in the NTT domain whose coefficients are all uninitialized.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::prelude::{GlweSize, PolynomialSize};
    /// let glwe: NttGlweCiphertext<Vec<ModQ<u64>>> =
    ///     NttGlweCiphertext::allocate(ModQ::new(0u64, MOD_32_128), PolynomialSize(10), GlweSize(7));
    /// assert_eq!(glwe.glwe_size(), GlweSize(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn allocate(
        value: ModQ<NttScalar>,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> Self {
        let tensor = Tensor::from_container(vec![value; glwe_size.0 * poly_size.0]);
        NttGlweCiphertext {
            tensor,
            poly_size,
            glwe_size,
        }
    }
}

impl<Cont> NttGlweCiphertext<Cont> {
    /// Creates a GLWE ciphertext in the NTT domain from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::prelude::{GlweSize, PolynomialSize};
    ///
    /// let glwe: NttGlweCiphertext<Vec<ModQ<u64>>> = NttGlweCiphertext::from_container(
    ///     vec![ModQ::new(0u64, MOD_32_128); 7 * 10],
    ///     GlweSize(7),
    ///     PolynomialSize(10),
    /// );
    /// assert_eq!(glwe.glwe_size(), GlweSize(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn from_container(cont: Cont, glwe_size: GlweSize, poly_size: PolynomialSize) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => glwe_size.0, poly_size.0);
        NttGlweCiphertext {
            tensor,
            poly_size,
            glwe_size,
        }
    }

    /// Returns the size of the GLWE ciphertext
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::prelude::{GlweSize, PolynomialSize};
    ///
    /// let glwe: NttGlweCiphertext<Vec<ModQ<u64>>> =
    ///     NttGlweCiphertext::allocate(ModQ::new(0u64, MOD_32_128), PolynomialSize(10), GlweSize(7));
    /// assert_eq!(glwe.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize
    where
        Cont: AsRefSlice,
    {
        self.glwe_size
    }

    /// Returns the size of the polynomials used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::MOD_32_128;
    /// use concrete_core::prelude::{GlweSize, PolynomialSize};
    ///
    /// let glwe: NttGlweCiphertext<Vec<ModQ<u64>>> =
    ///     NttGlweCiphertext::allocate(ModQ::new(0u64, MOD_32_128), PolynomialSize(10), GlweSize(7));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Fills an NTT GLWE ciphertext with the NTT transform of a GLWE ciphertext in
    /// coefficient domain.
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::{
    ///     INVROOTS_32_128, MOD_32_128, NINV_32_128, ROOTS_32_128,
    /// };
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::commons::crypto::glwe::GlweCiphertext;
    /// use concrete_core::prelude::{GlweSize, PolynomialSize, PolynomialSizeLog};
    /// let mut ntt_glwe: NttGlweCiphertext<Vec<ModQ<u64>>> = NttGlweCiphertext::allocate(
    ///     ModQ::new(0u64, MOD_32_128),
    ///     PolynomialSize(128),
    ///     GlweSize(7),
    /// );
    ///
    /// let glwe = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    /// let poly_size = PolynomialSize(128);
    /// let log_size = PolynomialSizeLog(7);
    /// let q: u64 = MOD_32_128;
    /// let roots: Vec<ModQ<u64>> = ROOTS_32_128
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let roots_inv: Vec<ModQ<u64>> = INVROOTS_32_128
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let n_inv = ModQ::new(NINV_32_128, q);
    /// let mut ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    ///
    /// ntt_glwe.fill_with_forward_ntt(&glwe, &mut ntt);
    /// ```
    pub fn fill_with_forward_ntt<InputCont, Scalar, NttScalar>(
        &mut self,
        glwe: &GlweCiphertext<InputCont>,
        ntt: &mut Ntt<NttScalar>,
    ) where
        Cont: AsMutSlice<Element = ModQ<NttScalar>>,
        InputCont: AsRefSlice<Element = Scalar>,
        Scalar: UnsignedTorus + CastInto<NttScalar>,
        NttScalar: UnsignedInteger,
    {
        let glwe_polys = glwe.as_polynomial_list();
        let iterator = self.polynomial_iter_mut().zip(glwe_polys.polynomial_iter());
        for (mut ntt_poly, coef_poly) in iterator {
            ntt.forward_w_mod_switch(&mut ntt_poly, &coef_poly);
        }
    }

    /// Fills a GLWE ciphertext with the inverse transform of an NTT GLWE ciphertext
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::{
    ///     INVROOTS_32_128, MOD_32_128, NINV_32_128, ROOTS_32_128,
    /// };
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::commons::crypto::glwe::GlweCiphertext;
    /// use concrete_core::prelude::{GlweSize, PolynomialSize, PolynomialSizeLog};
    /// let mut ntt_glwe: NttGlweCiphertext<Vec<ModQ<u64>>> = NttGlweCiphertext::allocate(
    ///     ModQ::new(0u64, MOD_32_128),
    ///     PolynomialSize(128),
    ///     GlweSize(7),
    /// );
    ///
    /// let glwe = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    /// let poly_size = PolynomialSize(128);
    /// let log_size = PolynomialSizeLog(7);
    /// let q: u64 = MOD_32_128;
    /// let roots: Vec<ModQ<u64>> = ROOTS_32_128
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let roots_inv: Vec<ModQ<u64>> = INVROOTS_32_128
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let n_inv = ModQ::new(NINV_32_128, q);
    /// let mut ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    ///
    /// ntt_glwe.fill_with_forward_ntt(&glwe, &mut ntt);
    ///
    /// let mut glwe_out = GlweCiphertext::allocate(0 as u32, PolynomialSize(128), GlweSize(7));
    ///
    /// ntt_glwe.fill_with_backward_ntt(&mut glwe_out, &mut ntt);
    /// ```
    pub fn fill_with_backward_ntt<InputCont, Scalar, NttScalar>(
        &mut self,
        glwe: &mut GlweCiphertext<InputCont>,
        ntt: &mut Ntt<NttScalar>,
    ) where
        Cont: AsMutSlice<Element = ModQ<NttScalar>>,
        InputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus + CastFrom<NttScalar>,
        NttScalar: UnsignedInteger,
    {
        let mut poly_list = glwe.as_mut_polynomial_list();
        let iterator = poly_list
            .polynomial_iter_mut()
            .zip(self.polynomial_iter_mut());
        for (mut coef_poly, ntt_poly) in iterator {
            ntt.backward_w_mod_switch(&mut coef_poly, &ntt_poly);
        }
    }

    /// Returns an iterator over references to the polynomials contained in the GLWE.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::commons::math::polynomial::PolynomialList;
    /// use concrete_core::prelude::PolynomialSize;
    /// let mut list =
    ///     PolynomialList::from_container(vec![1u8, 2, 3, 4, 5, 6, 7, 8], PolynomialSize(2));
    /// for polynomial in list.polynomial_iter() {
    ///     assert_eq!(polynomial.polynomial_size(), PolynomialSize(2));
    /// }
    /// assert_eq!(list.polynomial_iter().count(), 4);
    /// ```
    pub fn polynomial_iter(
        &self,
    ) -> impl Iterator<Item = NttPolynomial<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.poly_size.0)
            .map(NttPolynomial::from_tensor)
    }

    /// Returns an iterator over mutable references to the polynomials contained in the list.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::commons::math::polynomial::PolynomialList;
    /// use concrete_core::prelude::{MonomialDegree, PolynomialSize};
    /// let mut list =
    ///     PolynomialList::from_container(vec![1u8, 2, 3, 4, 5, 6, 7, 8], PolynomialSize(2));
    /// for mut polynomial in list.polynomial_iter_mut() {
    ///     polynomial
    ///         .get_mut_monomial(MonomialDegree(0))
    ///         .set_coefficient(10u8);
    ///     assert_eq!(polynomial.polynomial_size(), PolynomialSize(2));
    /// }
    /// for polynomial in list.polynomial_iter() {
    ///     assert_eq!(
    ///         *polynomial.get_monomial(MonomialDegree(0)).get_coefficient(),
    ///         10u8
    ///     );
    /// }
    /// assert_eq!(list.polynomial_iter_mut().count(), 4);
    /// ```
    pub fn polynomial_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = NttPolynomial<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(NttPolynomial::from_tensor)
    }
}

impl<Element, Cont> AsRefTensor for NttGlweCiphertext<Cont>
where
    Cont: AsRefSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.tensor
    }
}

impl<Element, Cont> AsMutTensor for NttGlweCiphertext<Cont>
where
    Cont: AsMutSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.tensor
    }
}

impl<Cont> IntoTensor for NttGlweCiphertext<Cont>
where
    Cont: AsRefSlice,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.tensor
    }
}
