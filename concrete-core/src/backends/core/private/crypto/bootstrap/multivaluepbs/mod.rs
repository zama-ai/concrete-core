#[cfg(test)]
mod test;

use crate::backends::core::private::crypto::bootstrap::fourier::constant_sample_extract;
use crate::backends::core::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::core::private::crypto::glwe::GlweCiphertext;
use crate::backends::core::private::crypto::lwe::LweCiphertext;
use crate::backends::core::private::math::fft::{AlignedVec, Complex64, Fft, FourierPolynomial};
use crate::backends::core::private::math::polynomial::Polynomial;
use crate::backends::core::private::math::tensor::{
    AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor,
};
use crate::backends::core::private::math::torus::UnsignedTorus;
use concrete_commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use concrete_commons::parameters::{MonomialDegree, PolynomialSize};

//Fourier polynomial generation
pub fn generate_fourier_polynomial_multivalue<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
) -> FourierPolynomial<AlignedVec<Complex64>>
where
    F: Fn(u64) -> u64,
{
    // N/(p/2) = size of each block
    let box_size = poly_size.0 / modulus;

    // Create the accumulator
    let mut poly_acc = vec![0_u64; poly_size.0];

    // This accumulator extracts the carry bits
    for i in 0..modulus {
        let index = i as usize * box_size;
        poly_acc[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(i as u64));
    }

    let polynomial_accumulator = Polynomial::from_container(poly_acc);

    // println!("poly_res = {:?}", polynomial_accumulator);

    let mut cont = vec![0_u64; poly_size.0];

    cont[0] = 1;
    cont[1] = 1_u64.wrapping_neg();

    //poly = 1 - X
    let poly = Polynomial::from_container(cont);

    fourier_multiplication_integer_integer_fourier(&polynomial_accumulator, &poly)
    // let res = karatsuba_multiplication(&polynomial_accumulator, &poly);
}

pub fn generate_polynomial_multivalue<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
) -> Polynomial<Vec<u64>>
where
    F: Fn(u64) -> u64,
{
    let cont = vec![0_u64; poly_size.0];
    let mut res = Polynomial::from_container(cont);
    let fft = Fft::new(poly_size);

    let mut fourier_res = generate_fourier_polynomial_multivalue(f, modulus, poly_size);

    fft.add_backward_as_integer(&mut res, &mut fourier_res);

    res
}

pub fn generate_fourier_polynomial_multivalue_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
) -> FourierPolynomial<AlignedVec<Complex64>>
where
    F: Fn(u64) -> u64,
{
    // N/(p/2) = size of each block
    let box_size = poly_size.0 / modulus;

    // Create the accumulator
    let mut poly_acc = vec![0_u64; poly_size.0];

    for i in 0..modulus {
        let index = i as usize * box_size;
        poly_acc[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(i as u64 % base as u64));
    }

    let polynomial_accumulator = Polynomial::from_container(poly_acc);

    // println!("poly_res = {:?}", polynomial_accumulator);

    let mut cont = vec![0_u64; poly_size.0];

    cont[0] = 1;
    cont[1] = 1_u64.wrapping_neg();

    //poly = 1 - X
    let poly = Polynomial::from_container(cont);

    fourier_multiplication_integer_integer_fourier(&polynomial_accumulator, &poly)
}

pub fn generate_polynomial_multivalue_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
) -> Polynomial<Vec<u64>>
where
    F: Fn(u64) -> u64,
{
    let cont = vec![0_u64; poly_size.0];
    let mut res = Polynomial::from_container(cont);
    let fft = Fft::new(poly_size);

    let mut fourier_res = generate_fourier_polynomial_multivalue_base(f, modulus, base, poly_size);

    fft.add_backward_as_integer(&mut res, &mut fourier_res);

    res
}

pub fn generate_polynomial_two_variables<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<Polynomial<Vec<u64>>>,
) where
    F: Fn(u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64| f(x, i as u64);

        poly_acc.push(generate_polynomial_multivalue(|x| g(x), modulus, poly_size));
    }
}

pub fn generate_fourier_polynomial_two_variables<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<FourierPolynomial<AlignedVec<Complex64>>>,
) where
    F: Fn(u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64| f(x, i as u64);

        poly_acc.push(generate_fourier_polynomial_multivalue(
            |x| g(x),
            modulus,
            poly_size,
        ));
    }
}

pub fn generate_polynomial_two_variables_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<Polynomial<Vec<u64>>>,
) where
    F: Fn(u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64| f(x, i as u64);

        poly_acc.push(generate_polynomial_multivalue_base(
            |x| g(x),
            modulus,
            base,
            poly_size,
        ));
    }
}

pub fn generate_fourier_polynomial_two_variables_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<FourierPolynomial<AlignedVec<Complex64>>>,
) where
    F: Fn(u64, u64) -> u64,
{
    for i in 0..base {
        let g = |x: u64| f(x, i as u64);

        poly_acc.push(generate_fourier_polynomial_multivalue_base(
            |x| g(x),
            modulus,
            base,
            poly_size,
        ));
    }
}

pub fn generate_polynomial_three_variables<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<Polynomial<Vec<u64>>>,
) where
    F: Fn(u64, u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64, y: u64| f(x, y, i as u64);

        generate_polynomial_two_variables(|x, y| g(x, y), modulus, poly_size, poly_acc);
    }
}

pub fn generate_fourier_polynomial_three_variables<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<FourierPolynomial<AlignedVec<Complex64>>>,
) where
    F: Fn(u64, u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64, y: u64| f(x, y, i as u64);

        generate_fourier_polynomial_two_variables(|x, y| g(x, y), modulus, poly_size, poly_acc);
    }
}

pub fn generate_fourier_polynomial_three_variables_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<FourierPolynomial<AlignedVec<Complex64>>>,
) where
    F: Fn(u64, u64, u64) -> u64,
{
    for i in 0..base {
        let g = |x: u64, y: u64| f(x, y, i as u64);

        generate_fourier_polynomial_two_variables_base(
            |x, y| g(x, y),
            modulus,
            base,
            poly_size,
            poly_acc,
        );
    }
}

pub fn generate_polynomial_four_variables<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<Polynomial<Vec<u64>>>,
) where
    F: Fn(u64, u64, u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64, y: u64, z: u64| f(x, y, z, i as u64);

        generate_polynomial_three_variables(|x, y, z| g(x, y, z), modulus, poly_size, poly_acc);
    }
}

pub fn generate_fourier_polynomial_four_variables<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<FourierPolynomial<AlignedVec<Complex64>>>,
) where
    F: Fn(u64, u64, u64, u64) -> u64,
{
    for i in 0..modulus {
        let g = |x: u64, y: u64, z: u64| f(x, y, z, i as u64);

        generate_fourier_polynomial_three_variables(
            |x, y, z| g(x, y, z),
            modulus,
            poly_size,
            poly_acc,
        );
    }
}

pub fn generate_fourier_polynomial_four_variables_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
    poly_acc: &mut Vec<FourierPolynomial<AlignedVec<Complex64>>>,
) where
    F: Fn(u64, u64, u64, u64) -> u64,
{
    for i in 0..base {
        let g = |x: u64, y: u64, z: u64| f(x, y, z, i as u64);

        generate_fourier_polynomial_three_variables_base(
            |x, y, z| g(x, y, z),
            modulus,
            base,
            poly_size,
            poly_acc,
        );
    }
}

impl<Cont, Scalar> FourierBootstrapKey<Cont, Scalar>
where
    GlweCiphertext<Vec<Scalar>>: AsRefTensor<Element = Scalar>,
    Self: AsRefTensor<Element = Complex64>,
    Scalar: UnsignedTorus + CastInto<u64>,
    u64: CastFrom<Scalar>,
{
    ///Returns BlindRotate( (1/2) * (1+X+...+X^{N-1}) * shift, ctxt )
    pub fn create_common_accumulator<C1>(
        &self,
        ct_in: &LweCiphertext<C1>,
        modulus: Scalar,
        buffers: &mut FourierBuffers<Scalar>,
        // glwe_sk: &GlweSecretKey<BinaryKeyKind, Vec<Scalar>>,
    ) -> GlweCiphertext<Vec<Scalar>>
    where
        C1: AsRefSlice<Element = Scalar>,
    {
        // Value of the shift we multiply our messages by
        let half_delta = (Scalar::ONE << (Scalar::BITS - 1)) / (Scalar::TWO * modulus);

        let polynomial_size = self.polynomial_size().0;

        // Create the GlweCiphertext64
        //====================================================================
        let mut values = vec![half_delta; 2 * polynomial_size];

        values[..polynomial_size].fill(Scalar::ZERO);
        //====================================================================

        // We retrieve the accumulator buffer, and fill it with the input accumulator values.
        let local_accumulator = &mut buffers.lut_buffer;
        local_accumulator
            .as_mut_tensor()
            .as_mut_slice()
            .copy_from_slice(values.as_slice());

        self.blind_rotate(buffers, ct_in);

        let mod_u64: u64 = modulus.cast_into();

        // N/(p/2) = size of each block
        let box_size = polynomial_size / mod_u64 as usize;

        let half_box_size = box_size / 2;

        for mut b_i in buffers
            .lut_buffer
            .as_mut_polynomial_list()
            .polynomial_iter_mut()
        {
            b_i.update_with_wrapping_unit_monomial_div(MonomialDegree(half_box_size));
        }

        buffers.lut_buffer.clone()
    }

    // pub fn multivalue_programmable_bootstrap<C1>(
    //     &self,
    //     ct_in: &LweCiphertext<C1>,
    //     modulus: Scalar,
    //     poly_acc: &[Polynomial<Vec<Scalar>>],
    //     buffers: &mut FourierBuffers<Scalar>,
    //     // ksk: &LweKeyswitchKey<Vec<Scalar>>,
    //     // glwe_sk: &GlweSecretKey<BinaryKeyKind, Vec<Scalar>>,
    //     // lwe_sk: &LweSecretKey<BinaryKeyKind, Vec<Scalar>>,
    // ) -> Vec<LweCiphertext<Vec<Scalar>>>
    // where
    //     C1: AsRefSlice<Element = Scalar>,
    // {
    //     let mut acc = self.create_common_accumulator(ct_in, modulus, buffers);
    //
    //     //To make the borrow checker happy
    //     let glwe_mask = acc.get_mask();
    //     let glwe_mask_poly = glwe_mask.as_polynomial_list();
    //     let mask = glwe_mask_poly.get_polynomial(0);
    //
    //     //To make the borrow checker happy
    //     let glwe_body = acc.get_body();
    //     let body = glwe_body.as_polynomial();
    //
    //     let empty_lwe = LweCiphertext::allocate(Scalar::ZERO, self.output_lwe_dimension().to_lwe_size());
    //     let mut res = vec![empty_lwe.clone(); poly_acc.len()];
    //
    //     //Fourier transform mask and body
    //     let fft = Fft::new(self.polynomial_size());
    //
    //     for (poly_in, res_out) in poly_acc.iter().zip(res.iter_mut()) {
    //         //Multiply the accumulator by the polynomial
    //         let mut mask_out = fourier_multiplication_torus_integer(&fft, poly_in, &mask);
    //         let body_out = fourier_multiplication_torus_integer(&fft, poly_in, &body);
    //
    //         let mut mask_and_body = mask_out.tensor.into_container();
    //
    //         mask_and_body.extend_from_slice(body_out.tensor.as_slice());
    //
    //         let acc_tmp = GlweCiphertext::from_container(mask_and_body, self.polynomial_size());
    //
    //         constant_sample_extract(res_out, &acc_tmp);
    //     }
    //
    //     // res
    //     res
    // }

    pub fn multivalue_programmable_bootstrap<C1>(
        &self,
        ct_in: &LweCiphertext<C1>,
        modulus: Scalar,
        poly_acc: &[FourierPolynomial<AlignedVec<Complex64>>],
        buffers: &mut FourierBuffers<Scalar>,
        // ksk: &LweKeyswitchKey<Vec<Scalar>>,
        // glwe_sk: &GlweSecretKey<BinaryKeyKind, Vec<Scalar>>,
        // lwe_sk: &LweSecretKey<BinaryKeyKind, Vec<Scalar>>,
    ) -> Vec<LweCiphertext<Vec<Scalar>>>
    where
        C1: AsRefSlice<Element = Scalar>,
    {
        let acc = self.create_common_accumulator(ct_in, modulus, buffers);

        //To make the borrow checker happy
        let glwe_mask = acc.get_mask();
        let glwe_mask_poly = glwe_mask.as_polynomial_list();
        let mask = glwe_mask_poly.get_polynomial(0);

        //To make the borrow checker happy
        let glwe_body = acc.get_body();
        let body = glwe_body.as_polynomial();

        let empty_lwe =
            LweCiphertext::allocate(Scalar::ZERO, self.output_lwe_dimension().to_lwe_size());
        let mut res = vec![empty_lwe.clone(); poly_acc.len()];

        //Fourier transform mask and body
        let fft = Fft::new(self.polynomial_size());
        let mut fourier_mask =
            FourierPolynomial::allocate(Complex64::new(0., 0.), self.polynomial_size());
        let mut fourier_body =
            FourierPolynomial::allocate(Complex64::new(0., 0.), self.polynomial_size());
        fft.forward_as_torus(&mut fourier_mask, &mask);
        fft.forward_as_torus(&mut fourier_body, &body);

        for (poly_in, res_out) in poly_acc.iter().zip(res.iter_mut()) {
            //Multiply the accumulator by the polynomial
            let mask_out =
                fourier_multiplication_torus_integer_fourier(&fft, poly_in, &fourier_mask);
            let body_out =
                fourier_multiplication_torus_integer_fourier(&fft, poly_in, &fourier_body);

            let mut mask_and_body = mask_out.tensor.into_container();

            mask_and_body.extend_from_slice(body_out.tensor.as_slice());

            let acc_tmp = GlweCiphertext::from_container(mask_and_body, self.polynomial_size());

            constant_sample_extract(res_out, &acc_tmp);
        }

        // res
        res
    }
}

///The biggest polynomial has to be given as the first parameter
pub fn fourier_multiplication_torus_integer<C1, C2, Scalar>(
    fft: &Fft,
    poly1: &Polynomial<C1>,
    poly2: &Polynomial<C2>,
) -> Polynomial<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
    Polynomial<C1>: AsRefTensor<Element = Scalar>,
    Polynomial<C2>: AsRefTensor<Element = Scalar>,
{
    //Allocate the polynomials
    //=======================================================================
    let poly_size = poly1.polynomial_size();
    let mut fourier_1 = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let mut fourier_2 = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let mut fourier_result = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);

    let cont = vec![Scalar::ZERO; poly_size.0];

    let mut result = Polynomial::from_container(cont);
    //=======================================================================

    //Transform to Fourier
    fft.forward_as_torus(&mut fourier_1, poly1);
    fft.forward_as_integer(&mut fourier_2, poly2);

    //Perform the multiplication
    fourier_result.update_with_multiply_accumulate(&fourier_1, &fourier_2);

    //Retrieve the polynomials
    fft.add_backward_as_torus(&mut result, &mut fourier_result);

    result
}

///The biggest polynomial has to be given as the first parameter
pub fn fourier_multiplication_integer_integer<C1, C2, Scalar>(
    poly1: &Polynomial<C1>,
    poly2: &Polynomial<C2>,
) -> Polynomial<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
    Polynomial<C1>: AsRefTensor<Element = Scalar>,
    Polynomial<C2>: AsRefTensor<Element = Scalar>,
{
    //Allocate the polynomials
    //=======================================================================
    let poly_size = poly1.polynomial_size();
    let fft = Fft::new(poly_size);
    let mut fourier_1 = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let mut fourier_2 = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let mut fourier_result = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);

    let cont = vec![Scalar::ZERO; poly_size.0];

    let mut result = Polynomial::from_container(cont);
    //=======================================================================

    fft.forward_two_as_integer(&mut fourier_1, &mut fourier_2, poly1, poly2);

    //Perform the multiplication
    fourier_result.update_with_multiply_accumulate(&fourier_1, &fourier_2);

    //Retrieve the polynomials
    fft.add_backward_as_integer(&mut result, &mut fourier_result);

    result
}

///The biggest polynomial has to be given as the first parameter
pub fn fourier_multiplication_torus_integer_fourier<Scalar>(
    fft: &Fft,
    poly1: &FourierPolynomial<AlignedVec<Complex64>>,
    poly2: &FourierPolynomial<AlignedVec<Complex64>>,
) -> Polynomial<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    //Allocate the polynomials
    //=======================================================================
    let poly_size = poly1.polynomial_size();
    let mut fourier_result = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let cont = vec![Scalar::ZERO; poly_size.0];
    let mut result = Polynomial::from_container(cont);
    //=======================================================================

    //Perform the multiplication
    fourier_result.update_with_multiply_accumulate(&poly1, &poly2);

    //Retrieve the polynomials
    fft.add_backward_as_torus(&mut result, &mut fourier_result);

    result
}

///The biggest polynomial has to be given as the first parameter
pub fn fourier_multiplication_integer_integer_fourier<C1, C2, Scalar>(
    poly1: &Polynomial<C1>,
    poly2: &Polynomial<C2>,
) -> FourierPolynomial<AlignedVec<Complex64>>
where
    Scalar: UnsignedTorus,
    Polynomial<C1>: AsRefTensor<Element = Scalar>,
    Polynomial<C2>: AsRefTensor<Element = Scalar>,
{
    //Allocate the polynomials
    //=======================================================================
    let poly_size = poly1.polynomial_size();
    let fft = Fft::new(poly_size);
    let mut fourier_1 = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let mut fourier_2 = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    let mut fourier_result = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
    //=======================================================================

    fft.forward_two_as_integer(&mut fourier_1, &mut fourier_2, poly1, poly2);

    //Perform the multiplication
    fourier_result.update_with_multiply_accumulate(&fourier_1, &fourier_2);

    fourier_result
}

pub fn karatsuba_multiplication<Coef, LhsCont, RhsCont>(
    poly_1: &Polynomial<LhsCont>,
    poly_2: &Polynomial<RhsCont>,
) -> Polynomial<Vec<Coef>>
where
    Polynomial<LhsCont>: AsRefTensor<Element = Coef>,
    Polynomial<RhsCont>: AsRefTensor<Element = Coef>,
    Coef: UnsignedInteger,
{
    let mut witness = Polynomial::allocate(Coef::ZERO, poly_1.polynomial_size());
    witness.fill_with_karatsuba_mul(&poly_1, &poly_2);
    witness
}
