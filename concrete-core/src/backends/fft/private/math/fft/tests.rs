use dyn_stack::{GlobalMemBuffer, ReborrowMut};

use super::super::super::super::private::math::polynomial::{FourierPolynomial, Polynomial};
use super::*;
use crate::commons::test_tools::new_random_generator;
use aligned_vec::avec;

fn abs_diff<Scalar: UnsignedTorus>(a: Scalar, b: Scalar) -> Scalar {
    if a > b {
        a - b
    } else {
        b - a
    }
}

fn test_roundtrip<Scalar: UnsignedTorus>() {
    let mut generator = new_random_generator();
    for i in 2..=10 {
        let size = 1_usize << i;

        let fft = Fft::new(PolynomialSize(size));
        let fft = fft.as_view();

        let mut poly = Polynomial {
            data: avec![Scalar::ZERO; size].into_boxed_slice(),
        };
        let mut roundtrip = Polynomial {
            data: avec![Scalar::ZERO; size].into_boxed_slice(),
        };
        let mut fourier = FourierPolynomial {
            data: avec![c64::default(); size / 2].into_boxed_slice(),
        };

        for x in poly.data.iter_mut() {
            *x = generator.random_uniform();
        }

        let mut mem = GlobalMemBuffer::new(
            fft.forward_scratch()
                .unwrap()
                .and(fft.backward_scratch().unwrap()),
        );
        let mut stack = DynStack::new(&mut mem);

        fft.forward_as_torus(
            unsafe { fourier.as_mut_view().into_uninit() },
            poly.as_view(),
            stack.rb_mut(),
        );
        fft.backward_as_torus(
            unsafe { roundtrip.as_mut_view().into_uninit() },
            fourier.as_view(),
            stack.rb_mut(),
        );

        for (expected, actual) in izip!(&*poly.data, &*roundtrip.data) {
            assert!(abs_diff(*expected, *actual) < (Scalar::ONE << (Scalar::BITS - 10)));
        }
    }
}

fn test_product<Scalar: UnsignedTorus>() {
    fn convolution_naive<Scalar: UnsignedTorus>(
        out: &mut [Scalar],
        lhs: &[Scalar],
        rhs: &[Scalar],
    ) {
        assert_eq!(out.len(), lhs.len());
        assert_eq!(out.len(), rhs.len());
        let n = out.len();
        let mut full_prod = vec![Scalar::ZERO; 2 * n];
        for i in 0..n {
            for j in 0..n {
                full_prod[i + j] = full_prod[i + j].wrapping_add(lhs[i].wrapping_mul(rhs[j]));
            }
        }
        for i in 0..n {
            out[i] = full_prod[i].wrapping_sub(full_prod[i + n]);
        }
    }

    let mut generator = new_random_generator();
    for i in 1..=10 {
        for _ in 0..100 {
            let size = 1_usize << i;

            let fft = Fft::new(PolynomialSize(size));
            let fft = fft.as_view();

            let mut poly0 = Polynomial {
                data: avec![Scalar::ZERO; size].into_boxed_slice(),
            };
            let mut poly1 = Polynomial {
                data: avec![Scalar::ZERO; size].into_boxed_slice(),
            };

            let mut convolution_from_fft = Polynomial {
                data: avec![Scalar::ZERO; size].into_boxed_slice(),
            };
            let mut convolution_from_naive = Polynomial {
                data: avec![Scalar::ZERO; size].into_boxed_slice(),
            };

            let mut fourier0 = FourierPolynomial {
                data: avec![c64::default(); size / 2].into_boxed_slice(),
            };
            let mut fourier1 = FourierPolynomial {
                data: avec![c64::default(); size / 2 ].into_boxed_slice(),
            };

            for (x, y) in izip!(&mut *poly0.data, &mut *poly1.data) {
                *x = generator.random_uniform();
                *y = generator.random_uniform();
                if Scalar::BITS == 64 {
                    *x >>= 32;
                    *y >>= 32;
                } else {
                    *x >>= 16;
                    *y >>= 16;
                }
            }

            let mut mem = GlobalMemBuffer::new(
                fft.forward_scratch()
                    .unwrap()
                    .and(fft.backward_scratch().unwrap()),
            );
            let mut stack = DynStack::new(&mut mem);

            // SAFETY: forward_as_torus doesn't write any uninitialized values into its output
            fft.forward_as_torus(
                unsafe { fourier0.as_mut_view().into_uninit() },
                poly0.as_view(),
                stack.rb_mut(),
            );
            // SAFETY: forward_as_integer doesn't write any uninitialized values into its output
            fft.forward_as_integer(
                unsafe { fourier1.as_mut_view().into_uninit() },
                poly1.as_view(),
                stack.rb_mut(),
            );

            for (f0, f1) in izip!(&mut *fourier0.data, &*fourier1.data) {
                *f0 *= *f1;
            }

            // SAFETY: backward_as_torus doesn't write any uninitialized values into its output
            fft.backward_as_torus(
                unsafe { convolution_from_fft.as_mut_view().into_uninit() },
                fourier0.as_view(),
                stack.rb_mut(),
            );
            convolution_naive(&mut convolution_from_naive.data, &poly0.data, &poly1.data);

            for (expected, actual) in
                izip!(&*convolution_from_naive.data, &*convolution_from_fft.data)
            {
                assert!(abs_diff(*expected, *actual) < (Scalar::ONE << (Scalar::BITS - 5)));
            }
        }
    }
}

#[test]
fn test_product_u32() {
    test_product::<u32>();
}

#[test]
fn test_product_u64() {
    test_product::<u64>();
}

#[test]
fn test_roundtrip_u32() {
    test_roundtrip::<u32>();
}
#[test]
fn test_roundtrip_u64() {
    test_roundtrip::<u64>();
}
