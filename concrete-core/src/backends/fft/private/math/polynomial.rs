use super::super::{as_mut_uninit, c64};
use crate::commons::numeric::UnsignedInteger;

//--------------------------------------------------------------------------------
// Structure definitions
//--------------------------------------------------------------------------------

/// Polynomial in the standard domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polynomial<C> {
    pub data: C,
}

/// Polynomial in the Fourier domain.
///
/// # Note
///
/// Polynomials in the Fourier domain have half the size of the corresponding polynomials in
/// the standard domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierPolynomial<C> {
    pub data: C,
}

pub type PolynomialView<'a, Scalar> = Polynomial<&'a [Scalar]>;
pub type PolynomialMutView<'a, Scalar> = Polynomial<&'a mut [Scalar]>;
pub type FourierPolynomialView<'a> = FourierPolynomial<&'a [c64]>;
pub type FourierPolynomialMutView<'a> = FourierPolynomial<&'a mut [c64]>;

/// Polynomial in the standard domain, with possibly uninitialized coefficients.
///
/// This is used for the Fourier transforms to avoid the cost of initializing the output buffer,
/// which can be non negligible.
pub type PolynomialUninitMutView<'a, Scalar> = Polynomial<&'a mut [core::mem::MaybeUninit<Scalar>]>;

/// Polynomial in the Fourier domain, with possibly uninitialized coefficients.
///
/// This is used for the Fourier transforms to avoid the cost of initializing the output buffer,
/// which can be non negligible.
///
/// # Note
///
/// Polynomials in the Fourier domain have half the size of the corresponding polynomials in
/// the standard domain.
pub type FourierPolynomialUninitMutView<'a> =
    FourierPolynomial<&'a mut [core::mem::MaybeUninit<c64>]>;

impl<C> Polynomial<C> {
    pub fn as_view<Scalar>(&self) -> PolynomialView<'_, Scalar>
    where
        C: AsRef<[Scalar]>,
    {
        Polynomial {
            data: self.data.as_ref(),
        }
    }

    pub fn as_mut_view<Scalar>(&mut self) -> PolynomialMutView<'_, Scalar>
    where
        C: AsMut<[Scalar]>,
    {
        Polynomial {
            data: self.data.as_mut(),
        }
    }
}

impl<C> FourierPolynomial<C> {
    pub fn as_view(&self) -> FourierPolynomialView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierPolynomial {
            data: self.data.as_ref(),
        }
    }

    pub fn as_mut_view(&mut self) -> FourierPolynomialMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierPolynomial {
            data: self.data.as_mut(),
        }
    }
}

impl<'a, Scalar> PolynomialMutView<'a, Scalar> {
    /// # Safety
    ///
    /// No uninitialized values must be written into the output buffer when the borrow ends
    pub unsafe fn into_uninit(self) -> PolynomialUninitMutView<'a, Scalar> {
        PolynomialUninitMutView {
            data: as_mut_uninit(self.data),
        }
    }
}

impl<'a> FourierPolynomialMutView<'a> {
    /// # Safety
    ///
    /// No uninitialized values must be written into the output buffer when the borrow ends
    pub unsafe fn into_uninit(self) -> FourierPolynomialUninitMutView<'a> {
        FourierPolynomialUninitMutView {
            data: as_mut_uninit(self.data),
        }
    }
}

impl<'a, Scalar: UnsignedInteger> PolynomialMutView<'a, Scalar> {
    pub fn update_with_wrapping_unit_monomial_mul(self, monomial_degree: usize) {
        let full_cycles_count = monomial_degree / self.data.len();
        let remaining_degree = monomial_degree % self.data.len();
        if full_cycles_count % 2 == 1 {
            self.data.iter_mut().for_each(|a| *a = a.wrapping_neg());
        }
        self.data.rotate_right(remaining_degree);
        self.data
            .iter_mut()
            .take(remaining_degree)
            .for_each(|a| *a = a.wrapping_neg());
    }

    pub fn update_with_wrapping_unit_monomial_div(self, monomial_degree: usize) {
        let full_cycles_count = monomial_degree / self.data.len();
        let remaining_degree = monomial_degree % self.data.len();
        if full_cycles_count % 2 == 1 {
            self.data.iter_mut().for_each(|a| *a = a.wrapping_neg());
        }
        self.data.rotate_left(remaining_degree);
        self.data
            .iter_mut()
            .rev()
            .take(remaining_degree)
            .for_each(|a| *a = a.wrapping_neg());
    }
}
