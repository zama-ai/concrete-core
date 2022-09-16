use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::tensor::{
    ck_dim_eq, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::commons::numeric::UnsignedInteger;
use crate::commons::utils::{zip, zip_args};
use crate::prelude::PolynomialSize;

/// A polynomial in the NTT domain.
///
/// This structure represents a polynomial, which was put in the NTT domain.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ModQPolynomial<Cont> {
    tensor: Tensor<Cont>,
}

tensor_traits!(ModQPolynomial);

impl<N: UnsignedInteger> ModQPolynomial<Vec<ModQ<N>>> {
    /// Allocates a new polynomial over Z_q.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::ModQPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let modq_poly = ModQPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// assert_eq!(modq_poly.polynomial_size(), PolynomialSize(128));
    /// ```
    pub fn allocate(value: ModQ<N>, coef_count: PolynomialSize) -> Self {
        let tensor = Tensor::from_container(vec![value; coef_count.0]);
        ModQPolynomial { tensor }
    }
}

impl<Cont> ModQPolynomial<Cont> {
    /// Creates a polynomial over Z_q from an existing container of values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::ModQPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let mut vec: Vec<ModQ<u64>> = vec![ModQ::empty(); 128];
    /// let modq_poly = ModQPolynomial::from_container(vec.as_mut_slice());
    /// assert_eq!(modq_poly.polynomial_size(), PolynomialSize(128));
    /// ```
    pub fn from_container(cont: Cont) -> Self {
        ModQPolynomial {
            tensor: Tensor::from_container(cont),
        }
    }

    pub(crate) fn from_tensor(tensor: Tensor<Cont>) -> Self {
        ModQPolynomial { tensor }
    }

    /// Returns the number of coefficients in the polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::ModQPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let modq_poly = ModQPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// assert_eq!(modq_poly.polynomial_size(), PolynomialSize(128));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize
    where
        Self: AsRefTensor,
    {
        PolynomialSize(self.as_tensor().len())
    }

    /// Returns an iterator over borrowed polynomial coefficients.
    ///
    /// # Note
    ///
    /// We do not give any guarantee on the order of the coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::ModQPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let modq_poly = ModQPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// for coef in modq_poly.coefficient_iter() {
    ///     assert_eq!(*coef, ModQ::new(0, 257u64));
    /// }
    /// assert_eq!(modq_poly.coefficient_iter().count(), 128);
    /// ```
    pub fn coefficient_iter<N: UnsignedInteger>(&self) -> impl Iterator<Item = &ModQ<N>>
    where
        Self: AsRefTensor<Element = ModQ<N>>,
    {
        self.as_tensor().iter()
    }

    /// Returns an iterator over mutably borrowed polynomial coefficients.
    ///
    /// # Note
    ///
    /// We do not give any guarantee on the order of the coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::ModQPolynomial;
    /// use concrete_core::commons::math::tensor::AsRefTensor;
    /// use concrete_core::prelude::PolynomialSize;
    /// let mut modq_poly = ModQPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// for mut coef in modq_poly.coefficient_iter_mut() {
    ///     coef.set(259u64);
    /// }
    /// assert!(modq_poly.as_tensor().iter().all(|a| a.get() == 2u64));
    /// assert_eq!(modq_poly.coefficient_iter_mut().count(), 128);
    /// ```
    pub fn coefficient_iter_mut<N: UnsignedInteger>(&mut self) -> impl Iterator<Item = &mut ModQ<N>>
    where
        Self: AsMutTensor<Element = ModQ<N>>,
    {
        self.as_mut_tensor().iter_mut()
    }
}

impl<N, Cont> ModQPolynomial<Cont>
where
    N: UnsignedInteger,
    Cont: AsMutSlice<Element = ModQ<N>>,
{
    pub fn from_polynomial<InCont>(&mut self, poly: &Polynomial<InCont>)
    where
        InCont: AsRefSlice<Element = N>,
    {
        for (modq, n) in self.coefficient_iter_mut().zip(poly.coefficient_iter()) {
            modq.set(*n);
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct NttPolynomial<Cont>(ModQPolynomial<Cont>);

impl<N: UnsignedInteger> NttPolynomial<Vec<ModQ<N>>> {
    /// Allocates a new empty NTT polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let ntt_poly = NttPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// assert_eq!(ntt_poly.polynomial_size(), PolynomialSize(128));
    /// ```
    pub fn allocate(value: ModQ<N>, coef_count: PolynomialSize) -> Self {
        let modq_poly = ModQPolynomial::allocate(value, coef_count);
        NttPolynomial(modq_poly)
    }
}

impl<Cont> NttPolynomial<Cont> {
    /// Creates an NTT polynomial from an existing container of values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let mut vec: Vec<ModQ<u64>> = vec![ModQ::new(0, 257u64); 128];
    /// let ntt_poly = NttPolynomial::from_container(vec.as_mut_slice());
    /// assert_eq!(ntt_poly.polynomial_size(), PolynomialSize(128));
    /// ```
    pub fn from_container(cont: Cont) -> Self {
        NttPolynomial(ModQPolynomial::from_container(cont))
    }

    pub(crate) fn from_tensor(tensor: Tensor<Cont>) -> Self {
        NttPolynomial(ModQPolynomial::from_tensor(tensor))
    }

    /// Returns the number of coefficients in the polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let ntt_poly = NttPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// assert_eq!(ntt_poly.polynomial_size(), PolynomialSize(128));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize
    where
        Self: AsRefTensor,
    {
        PolynomialSize(self.as_tensor().len())
    }

    /// Returns an iterator over borrowed polynomial coefficients.
    ///
    /// # Note
    ///
    /// We do not give any guarantee on the order of the coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let ntt_poly = NttPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// for coef in ntt_poly.coefficient_iter() {
    ///     assert_eq!(*coef, ModQ::new(0, 257u64));
    /// }
    /// assert_eq!(ntt_poly.coefficient_iter().count(), 128);
    /// ```
    pub fn coefficient_iter<N: UnsignedInteger>(&self) -> impl Iterator<Item = &ModQ<N>>
    where
        Self: AsRefTensor<Element = ModQ<N>>,
    {
        self.as_tensor().iter()
    }

    /// Returns an iterator over mutably borrowed polynomial coefficients.
    ///
    /// # Note
    ///
    /// We do not give any guarantee on the order of the coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::commons::math::tensor::AsRefTensor;
    /// use concrete_core::prelude::PolynomialSize;
    /// let mut ntt_poly = NttPolynomial::allocate(ModQ::new(0, 257u64), PolynomialSize(128));
    /// for mut coef in ntt_poly.coefficient_iter_mut() {
    ///     coef.set(259u64);
    /// }
    /// assert!(ntt_poly.as_tensor().iter().all(|a| a.get() == 2u64));
    /// assert_eq!(ntt_poly.coefficient_iter_mut().count(), 128);
    /// ```
    pub fn coefficient_iter_mut<N: UnsignedInteger>(&mut self) -> impl Iterator<Item = &mut ModQ<N>>
    where
        Self: AsMutTensor<Element = ModQ<N>>,
    {
        self.as_mut_tensor().iter_mut()
    }

    /// Adds the result of the element-wise product of two polynomials to the current polynomial:
    /// $$
    /// self\[i\] = self\[i\] + poly_1\[i\] * poly_2\[i\]
    /// $$
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::prelude::PolynomialSize;
    /// let q = 257u64;
    /// let mut npoly1 = NttPolynomial::allocate(ModQ::new(250, q), PolynomialSize(128));
    /// let npoly2 = NttPolynomial::allocate(ModQ::new(3, q), PolynomialSize(128));
    /// let npoly3 = NttPolynomial::allocate(ModQ::new(5, q), PolynomialSize(128));
    /// npoly1.update_with_multiply_accumulate(&npoly2, &npoly3);
    /// assert!(npoly1.coefficient_iter().all(|a| a.get() == 8u64));
    /// ```
    pub fn update_with_multiply_accumulate<PolyCont1, PolyCont2, N>(
        &mut self,
        poly_1: &NttPolynomial<PolyCont1>,
        poly_2: &NttPolynomial<PolyCont2>,
    ) where
        Self: AsMutTensor<Element = ModQ<N>>,
        NttPolynomial<PolyCont1>: AsRefTensor<Element = ModQ<N>>,
        NttPolynomial<PolyCont2>: AsRefTensor<Element = ModQ<N>>,
        N: UnsignedInteger,
    {
        ck_dim_eq!(self.polynomial_size().0 => poly_1.polynomial_size().0, poly_2.polynomial_size().0);
        for zip_args!(res, coef_1, coef_2) in zip!(
            self.as_mut_tensor().iter_mut(),
            poly_1.as_tensor().iter(),
            poly_2.as_tensor().iter()
        ) {
            *res += *coef_1 * *coef_2;
        }
    }
}

impl<Element, Cont> AsRefTensor for NttPolynomial<Cont>
where
    Cont: AsRefSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.0.tensor
    }
}

impl<Element, Cont> AsMutTensor for NttPolynomial<Cont>
where
    Cont: AsMutSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;

    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.0.tensor
    }
}

impl<Cont> IntoTensor for NttPolynomial<Cont>
where
    Cont: AsRefSlice,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.0.tensor
    }
}
