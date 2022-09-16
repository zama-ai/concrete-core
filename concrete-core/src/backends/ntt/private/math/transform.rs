use crate::commons::numeric::{CastFrom, CastInto, UnsignedInteger};

use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::backends::ntt::private::math::polynomial::{ModQPolynomial, NttPolynomial};
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::math::torus::UnsignedTorus;
use crate::prelude::{PolynomialSize, PolynomialSizeLog};

use super::ALLOWED_POLY_SIZE;

/// A fast NTT transformer.
///
/// This transformer type allows to send polynomials of a fixed size, back and forth in the NTT
/// domain.
#[derive(Clone)]
pub struct Ntt<N: UnsignedInteger> {
    log_size: PolynomialSizeLog,
    roots: Vec<ModQ<N>>,
    roots_inv: Vec<ModQ<N>>,
    n_inv: ModQ<N>,
    buffer: ModQPolynomial<Vec<ModQ<N>>>,
}

impl<N: UnsignedInteger> Ntt<N> {
    /// Generates a new transformer for polynomials with given size and parameters.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_128::{
    ///     INVROOTS_32_128, MOD_32_128, NINV_32_128, ROOTS_32_128,
    /// };
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::prelude::{PolynomialSize, PolynomialSizeLog};
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
    /// let ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    /// ```
    pub fn new(
        poly_size: PolynomialSize,
        log_size: PolynomialSizeLog,
        roots: Vec<ModQ<N>>,
        roots_inv: Vec<ModQ<N>>,
        n_inv: ModQ<N>,
    ) -> Ntt<N> {
        let modulus = n_inv.get_mod();
        let buffer = ModQPolynomial::allocate(<ModQ<N>>::new(N::ZERO, modulus), poly_size);
        Ntt {
            log_size,
            roots,
            roots_inv,
            n_inv,
            buffer,
        }
    }

    pub fn get_zero_mod_q(&self) -> ModQ<N> {
        ModQ::new(N::ZERO, self.n_inv.get_mod())
    }

    /// First applies a modulus switch to the internal modulus to the `in_poly` polynomial,
    /// viewed as a polynomial of integer coefficients mod `Coef:MAX`. Then performs the
    /// forward NTT transform and stores the result in `out_poly`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_256::{
    ///     INVROOTS_32_256, MOD_32_256, NINV_32_256, ROOTS_32_256,
    /// };
    /// use concrete_core::backends::ntt::private::math::polynomial::NttPolynomial;
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::commons::math::polynomial::Polynomial;
    /// use concrete_core::commons::math::random::RandomGenerator;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{PolynomialSize, PolynomialSizeLog};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let poly_size = PolynomialSize(256);
    /// let log_size = PolynomialSizeLog(8);
    /// let q: u64 = MOD_32_256;
    /// let roots: Vec<ModQ<u64>> = ROOTS_32_256
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let roots_inv: Vec<ModQ<u64>> = INVROOTS_32_256
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let n_inv = ModQ::new(NINV_32_256, q);
    /// let mut ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    /// let mut ntt_poly = NttPolynomial::allocate(ModQ::empty(), PolynomialSize(256));
    /// let mut poly = Polynomial::allocate(0u32, PolynomialSize(256));
    /// generator.fill_tensor_with_random_uniform(&mut poly);
    /// ntt.forward_w_mod_switch(&mut ntt_poly, &poly);
    /// let mut out = Polynomial::allocate(0u32, PolynomialSize(256));
    /// ntt.backward_w_mod_switch(&mut out, &mut ntt_poly);
    ///
    /// assert_eq!(out.polynomial_size(), poly.polynomial_size());
    /// ```
    pub fn forward_w_mod_switch<InCont, OutCont, InCoef>(
        &mut self,
        out_poly: &mut NttPolynomial<OutCont>,
        in_poly: &Polynomial<InCont>,
    ) where
        InCont: AsRefSlice<Element = InCoef>,
        OutCont: AsMutSlice<Element = ModQ<N>>,
        InCoef: UnsignedTorus + CastInto<N>,
    {
        debug_assert!(
            ALLOWED_POLY_SIZE.contains(&out_poly.polynomial_size().0),
            "The size chosen is not valid ({}). Check ALLOWED_POLY_SIZE.",
            out_poly.polynomial_size().0
        );
        assert_eq!(out_poly.polynomial_size().0, in_poly.polynomial_size().0);
        let buffer = &mut self.buffer;

        // copy in_poly into buffer while applying modulus switch
        for (buf, pol) in buffer
            .coefficient_iter_mut()
            .zip(in_poly.coefficient_iter())
        {
            buf.mod_switch_into(*pol);
        }

        self.forward_from_buffer(out_poly);
    }

    /// Performs the forward NTT transform of the `in_poly` polynomial, viewed as a polynomial of
    /// integer coefficients mod the internal modulus, and stores the result in `out_poly`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_256::{
    ///     INVROOTS_32_256, MOD_32_256, NINV_32_256, ROOTS_32_256,
    /// };
    /// use concrete_core::backends::ntt::private::math::polynomial::{ModQPolynomial, NttPolynomial};
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::commons::math::polynomial::Polynomial;
    /// use concrete_core::commons::math::random::RandomGenerator;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{PolynomialSize, PolynomialSizeLog};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let poly_size = PolynomialSize(256);
    /// let log_size = PolynomialSizeLog(8);
    /// let q: u64 = MOD_32_256;
    /// let roots: Vec<ModQ<u64>> = ROOTS_32_256
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let roots_inv: Vec<ModQ<u64>> = INVROOTS_32_256
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let n_inv = ModQ::new(NINV_32_256, q);
    /// let mut ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    /// let mut ntt_poly = NttPolynomial::allocate(ModQ::empty(), PolynomialSize(256));
    /// let mut poly = Polynomial::allocate(0u64, PolynomialSize(256));
    /// generator.fill_tensor_with_random_uniform(&mut poly);
    /// let mut modq_poly = ModQPolynomial::allocate(ntt.get_zero_mod_q(), PolynomialSize(256));
    /// modq_poly.from_polynomial(&poly);
    /// ntt.forward(&mut ntt_poly, &modq_poly);
    /// let mut out = ModQPolynomial::allocate(ntt.get_zero_mod_q(), PolynomialSize(256));
    /// ntt.backward(&mut out, &mut ntt_poly);
    ///
    /// out.as_tensor()
    ///     .iter()
    ///     .zip(modq_poly.as_tensor().iter())
    ///     .for_each(|(output, expected)| assert_eq!(*output, *expected));
    /// ```
    pub fn forward<InCont, OutCont>(
        &mut self,
        out_poly: &mut NttPolynomial<OutCont>,
        in_poly: &ModQPolynomial<InCont>,
    ) where
        InCont: AsRefSlice<Element = ModQ<N>>,
        OutCont: AsMutSlice<Element = ModQ<N>>,
    {
        debug_assert!(
            ALLOWED_POLY_SIZE.contains(&out_poly.polynomial_size().0),
            "The size chosen is not valid ({}). Check ALLOWED_POLY_SIZE.",
            out_poly.polynomial_size().0
        );
        assert_eq!(out_poly.polynomial_size().0, in_poly.polynomial_size().0);
        let buffer = &mut self.buffer;

        // copy in_poly into buffer
        for (buf, pol) in buffer
            .coefficient_iter_mut()
            .zip(in_poly.coefficient_iter())
        {
            *buf = *pol;
        }

        self.forward_from_buffer(out_poly);
    }

    /// performs the NTT on the buffer and copies the result to the `out_poly`
    fn forward_from_buffer<OutCont>(&mut self, out_poly: &mut NttPolynomial<OutCont>)
    where
        OutCont: AsMutSlice<Element = ModQ<N>>,
    {
        let buffer = &mut self.buffer;
        let roots = &self.roots;
        let log_size = self.log_size.0;

        // We perform the forward ntt
        for scale in 0..log_size {
            let t: usize = 1 << (log_size - 1 - scale);
            let m: usize = 1 << scale;

            for i in 0..m {
                let j1: usize = 2 * i * t;
                let j2: usize = j1 + t - 1;
                let s = &roots[m + i];

                for j in j1..(j2 + 1) {
                    let u = *buffer.as_tensor().get_element(j);
                    let v = *buffer.as_tensor().get_element(j + t) * (*s);
                    buffer.as_mut_tensor().set_element(j, u + v);
                    buffer.as_mut_tensor().set_element(j + t, u - v);
                }
            }
        }

        // copy result from buffer to out_poly
        for (out_coef, buf_coef) in out_poly
            .coefficient_iter_mut()
            .zip(buffer.coefficient_iter())
        {
            *out_coef = *buf_coef;
        }
    }

    /// Performs the backward NTT transform of the `in_poly` polynomial, viewed as a
    /// polynomial of integer coefficients mod the internal modulus and then applies a modulus
    /// switch to `Coef::MAX`.
    ///
    /// See [`Ntt::forward_w_mod_switch`] for an example.
    pub fn backward_w_mod_switch<InCont, OutCont, OutCoef>(
        &mut self,
        out_poly: &mut Polynomial<OutCont>,
        in_poly: &NttPolynomial<InCont>,
    ) where
        InCont: AsRefSlice<Element = ModQ<N>>,
        OutCont: AsMutSlice<Element = OutCoef>,
        OutCoef: UnsignedTorus + CastFrom<N>,
    {
        assert_eq!(out_poly.polynomial_size().0, in_poly.polynomial_size().0);

        self.backwards_into_buffer(in_poly);

        let buffer = &mut self.buffer;
        // copy result from buffer to out_poly while applying the modulus switch
        for (out_coef, buf_coef) in out_poly
            .coefficient_iter_mut()
            .zip(buffer.coefficient_iter())
        {
            *out_coef = (*buf_coef * self.n_inv).mod_switch_from();
        }
    }

    pub fn add_backward_w_mod_switch<InCont, OutCont, OutCoef>(
        &mut self,
        out_poly: &mut Polynomial<OutCont>,
        in_poly: &NttPolynomial<InCont>,
    ) where
        InCont: AsRefSlice<Element = ModQ<N>>,
        OutCont: AsMutSlice<Element = OutCoef>,
        OutCoef: UnsignedTorus + CastFrom<N>,
    {
        assert_eq!(out_poly.polynomial_size().0, in_poly.polynomial_size().0);

        self.backwards_into_buffer(in_poly);

        let buffer = &mut self.buffer;
        // add result from buffer to out_poly while applying the modulus switch
        for (out_coef, buf_coef) in out_poly
            .coefficient_iter_mut()
            .zip(buffer.coefficient_iter())
        {
            // *out_coef += (*buf_coef * self.n_inv).mod_switch_from();
            *out_coef = out_coef.wrapping_add((*buf_coef * self.n_inv).mod_switch_from());
        }
    }

    /// Performs the backward NTT transform of the `in_poly` polynomial, viewed as a
    /// polynomial of integer coefficients mod the internal modulus.
    ///
    /// See [`Ntt::backward`] for an example.
    pub fn backward<InCont, OutCont>(
        &mut self,
        out_poly: &mut ModQPolynomial<OutCont>,
        in_poly: &NttPolynomial<InCont>,
    ) where
        InCont: AsRefSlice<Element = ModQ<N>>,
        OutCont: AsMutSlice<Element = ModQ<N>>,
    {
        assert_eq!(out_poly.polynomial_size().0, in_poly.polynomial_size().0);
        // let params = self.params.get_mut(&in_poly.polynomial_size()).unwrap();

        self.backwards_into_buffer(in_poly);

        let buffer = &mut self.buffer;

        // copy result from buffer to out_poly
        for (out_coef, buf_coef) in out_poly
            .coefficient_iter_mut()
            .zip(buffer.coefficient_iter())
        {
            *out_coef = *buf_coef * self.n_inv;
        }
    }

    /// Copies `in_poly` to the buffer and performs the inverse NTT on it.
    fn backwards_into_buffer<InCont>(&mut self, in_poly: &NttPolynomial<InCont>)
    where
        InCont: AsRefSlice<Element = ModQ<N>>,
    {
        let buffer = &mut self.buffer;
        let roots_inv = &self.roots_inv;
        let log_size = self.log_size.0;

        for (buf, pol) in buffer
            .coefficient_iter_mut()
            .zip(in_poly.coefficient_iter())
        {
            *buf = *pol;
        }

        // We perform the backward ntt
        for scale in 0..log_size {
            let h: usize = 1 << (log_size - 1 - scale);
            let t: usize = 1 << scale;

            let mut j1: usize = 0;

            for i in 0..h {
                let j2: usize = j1 + t - 1;
                let s = &roots_inv[h + i];

                for j in j1..(j2 + 1) {
                    let u = *buffer.as_tensor().get_element(j);
                    let v = *buffer.as_tensor().get_element(j + t);
                    buffer.as_mut_tensor().set_element(j, u + v);
                    buffer.as_mut_tensor().set_element(j + t, (u - v) * (*s));
                }

                j1 += 2 * t;
            }
        }
    }
}
