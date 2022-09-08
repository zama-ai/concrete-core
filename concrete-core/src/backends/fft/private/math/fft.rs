use super::super::{assume_init_mut, c64, izip};
use super::polynomial::{
    FourierPolynomialMutView, FourierPolynomialUninitMutView, FourierPolynomialView,
    PolynomialMutView, PolynomialUninitMutView, PolynomialView,
};
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::CastInto;
use crate::prelude::PolynomialSize;
use aligned_vec::{avec, ABox};
use concrete_fft::unordered::{Method, Plan};
use dyn_stack::{DynStack, SizeOverflow, StackReq};
use once_cell::sync::OnceCell;
use std::any::TypeId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::mem::{align_of, size_of, MaybeUninit};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Twisting factors from the paper:
/// [Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform][paper]
///
/// The real and imaginary parts form (the first `N/2`) `2N`-th roots of unity.
///
/// [paper]: https://eprint.iacr.org/2021/480
#[derive(Clone, Debug, PartialEq)]
pub struct Twisties {
    re: ABox<[f64]>,
    im: ABox<[f64]>,
}

/// View type for [`Twisties`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TwistiesView<'a> {
    re: &'a [f64],
    im: &'a [f64],
}

impl Twisties {
    pub fn as_view(&self) -> TwistiesView<'_> {
        TwistiesView {
            re: &self.re,
            im: &self.im,
        }
    }
}

impl Twisties {
    /// Creates a new [`Twisties`] containing the `2N`-th roots of unity with `n = N/2`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is not a power of two.
    pub fn new(n: usize) -> Self {
        debug_assert!(n.is_power_of_two());
        let mut re = avec![0.0; n].into_boxed_slice();
        let mut im = avec![0.0; n].into_boxed_slice();

        let unit = core::f64::consts::PI / (2.0 * n as f64);
        for (i, (re, im)) in izip!(&mut *re, &mut *im).enumerate() {
            (*im, *re) = (i as f64 * unit).sin_cos();
        }

        Twisties { re, im }
    }
}

/// Negacyclic Fast Fourier Transform. See [`FftView`] for transform functions.
///
/// This structure contains the twisting factors as well as the
/// FFT plan needed for the negacyclic convolution over the reals.
#[derive(Clone, Debug)]
pub struct Fft {
    plan: Arc<(Twisties, Plan)>,
}

/// View type for [`Fft`].
#[derive(Clone, Copy, Debug)]
pub struct FftView<'a> {
    plan: &'a Plan,
    twisties: TwistiesView<'a>,
}

impl Fft {
    #[inline]
    pub fn as_view(&self) -> FftView<'_> {
        FftView {
            plan: &self.plan.1,
            twisties: self.plan.0.as_view(),
        }
    }
}

type PlanMap = RwLock<HashMap<usize, Arc<OnceCell<Arc<(Twisties, Plan)>>>>>;
static PLANS: OnceCell<PlanMap> = OnceCell::new();
fn plans() -> &'static PlanMap {
    PLANS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Returns the input slice, cast to the same type.
///
/// This is useful when the fact that `From` and `To` are the same type cannot be proven in the
/// type system, but is known to be true at runtime.
///
/// # Panics
///
/// Panics if `From` and `To` are not the same type
#[inline]
fn cast_same_type<From: 'static, To: 'static>(slice: &mut [From]) -> &mut [To] {
    assert_eq!(size_of::<From>(), size_of::<To>());
    assert_eq!(align_of::<From>(), align_of::<To>());
    assert_eq!(TypeId::of::<From>(), TypeId::of::<To>());

    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    unsafe { core::slice::from_raw_parts_mut(ptr as *mut To, len) }
}

impl Fft {
    /// Real polynomial of size `size`.
    pub fn new(size: PolynomialSize) -> Self {
        let global_plans = plans();

        let n = size.0;
        let get_plan = || {
            let plans = global_plans.read().unwrap();
            let plan = plans.get(&n).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| {
                    Arc::new((
                        Twisties::new(n / 2),
                        Plan::new(n / 2, Method::Measure(Duration::from_millis(10))),
                    ))
                })
                .clone()
            })
        };

        // could not find a plan of the given size, we lock the map again and try to insert it
        let mut plans = global_plans.write().unwrap();
        if let Entry::Vacant(v) = plans.entry(n) {
            v.insert(Arc::new(OnceCell::new()));
        }

        drop(plans);

        Self {
            plan: get_plan().unwrap(),
        }
    }
}

fn convert_forward_torus<Scalar: UnsignedTorus>(
    out: &mut [MaybeUninit<c64>],
    in_re: &[Scalar],
    in_im: &[Scalar],
    twisties: TwistiesView<'_>,
) {
    let normalization = 2.0_f64.powi(-(Scalar::BITS as i32));

    izip!(out, in_re, in_im, twisties.re, twisties.im).for_each(
        |(out, in_re, in_im, w_re, w_im)| {
            let in_re: f64 = in_re.into_signed().cast_into() * normalization;
            let in_im: f64 = in_im.into_signed().cast_into() * normalization;
            out.write(
                c64 {
                    re: in_re,
                    im: in_im,
                } * c64 {
                    re: *w_re,
                    im: *w_im,
                },
            );
        },
    );
}

fn convert_forward_integer<Scalar: UnsignedTorus>(
    out: &mut [MaybeUninit<c64>],
    in_re: &[Scalar],
    in_im: &[Scalar],
    twisties: TwistiesView<'_>,
) {
    izip!(out, in_re, in_im, twisties.re, twisties.im).for_each(
        |(out, in_re, in_im, w_re, w_im)| {
            let in_re: f64 = in_re.into_signed().cast_into();
            let in_im: f64 = in_im.into_signed().cast_into();
            out.write(
                c64 {
                    re: in_re,
                    im: in_im,
                } * c64 {
                    re: *w_re,
                    im: *w_im,
                },
            );
        },
    );
}

fn convert_backward_torus<Scalar: UnsignedTorus>(
    out_re: &mut [MaybeUninit<Scalar>],
    out_im: &mut [MaybeUninit<Scalar>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let normalization = 1.0 / inp.len() as f64;
    izip!(out_re, out_im, inp, twisties.re, twisties.im).for_each(
        |(out_re, out_im, inp, w_re, w_im)| {
            let tmp = inp
                * (c64 {
                    re: *w_re,
                    im: -*w_im,
                } * normalization);

            out_re.write(Scalar::from_torus(tmp.re));
            out_im.write(Scalar::from_torus(tmp.im));
        },
    );
}

/// Performs common work for `u32` and `u64`, used by the backward torus transformation.
///
/// # Safety
///
///  - `w_re.add(i)`, `w_im.add(i)`, and `inp.add(i)` must point to an array of at least 4
///  elements.
///  - `is_x86_feature_detected!("fma")` must be true.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[inline(always)]
unsafe fn convert_torus_prologue_fma(
    normalization: __m256d,
    w_re: *const f64,
    i: usize,
    w_im: *const f64,
    inp: *const c64,
    scaling: __m256d,
) -> (__m256d, __m256d) {
    let w_re = _mm256_mul_pd(normalization, _mm256_loadu_pd(w_re.add(i)));
    let w_im = _mm256_mul_pd(normalization, _mm256_loadu_pd(w_im.add(i)));

    // re0 im0
    // re1 im1
    // re2 im2
    // re3 im3
    let inp0 = _mm_loadu_pd(inp.add(i) as _);
    let inp1 = _mm_loadu_pd(inp.add(i + 1) as _);
    let inp2 = _mm_loadu_pd(inp.add(i + 2) as _);
    let inp3 = _mm_loadu_pd(inp.add(i + 3) as _);

    let inp_re01 = _mm_unpacklo_pd(inp0, inp1);
    let inp_im01 = _mm_unpackhi_pd(inp0, inp1);
    let inp_re23 = _mm_unpacklo_pd(inp2, inp3);
    let inp_im23 = _mm_unpackhi_pd(inp2, inp3);

    let inp_re = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_re01), inp_re23);
    let inp_im = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_im01), inp_im23);

    let mul_re = _mm256_fmadd_pd(inp_re, w_re, _mm256_mul_pd(inp_im, w_im));
    let mul_im = _mm256_fnmadd_pd(inp_re, w_im, _mm256_mul_pd(inp_im, w_re));

    const ROUNDING: i32 = _MM_FROUND_NINT | _MM_FROUND_NO_EXC;

    let fract_re = _mm256_sub_pd(mul_re, _mm256_round_pd::<ROUNDING>(mul_re));
    let fract_im = _mm256_sub_pd(mul_im, _mm256_round_pd::<ROUNDING>(mul_im));
    let fract_re = _mm256_round_pd::<ROUNDING>(_mm256_mul_pd(scaling, fract_re));
    let fract_im = _mm256_round_pd::<ROUNDING>(_mm256_mul_pd(scaling, fract_im));

    (fract_re, fract_im)
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
///  - `is_x86_feature_detected!("fma")` must be true.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[target_feature(enable = "fma")]
unsafe fn convert_add_backward_torus_u32_fma(
    out_re: &mut [MaybeUninit<u32>],
    out_im: &mut [MaybeUninit<u32>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let n = out_re.len();
    debug_assert_eq!(n % 4, 0);
    debug_assert_eq!(n, out_re.len());
    debug_assert_eq!(n, out_im.len());
    debug_assert_eq!(n, inp.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let normalization = _mm256_set1_pd(1.0 / n as f64);
    let scaling = _mm256_set1_pd(2.0_f64.powi(u32::BITS as i32));
    let out_re = out_re.as_mut_ptr() as *mut u32;
    let out_im = out_im.as_mut_ptr() as *mut u32;
    let inp = inp.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 4 {
        let i = i * 4;

        let (fract_re, fract_im) =
            convert_torus_prologue_fma(normalization, w_re, i, w_im, inp, scaling);

        let fract_re = _mm256_cvtpd_epi32(fract_re);
        let fract_im = _mm256_cvtpd_epi32(fract_im);
        _mm_storeu_si128(
            out_re.add(i) as _,
            _mm_add_epi32(fract_re, _mm_loadu_si128(out_re.add(i) as _)),
        );
        _mm_storeu_si128(
            out_im.add(i) as _,
            _mm_add_epi32(fract_im, _mm_loadu_si128(out_im.add(i) as _)),
        );
    }
}

/// Performs common work for `u32` and `u64`, used by the backward torus transformation.
///
/// # Safety
///
///  - `w_re.add(i)`, `w_im.add(i)`, and `inp.add(i)` must point to an array of at least 8
///  elements.
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(all(
    feature = "backend_fft_nightly_avx512",
    any(target_arch = "x86_64", target_arch = "x86")
))]
#[inline(always)]
unsafe fn convert_torus_prologue_avx512f(
    normalization: __m512d,
    w_re: *const f64,
    i: usize,
    w_im: *const f64,
    inp: *const c64,
    scaling: __m512d,
) -> (__m512d, __m512d) {
    let w_re = _mm512_mul_pd(normalization, _mm512_loadu_pd(w_re.add(i)));
    let w_im = _mm512_mul_pd(normalization, _mm512_loadu_pd(w_im.add(i)));

    // re0 im0
    // re1 im1
    // re2 im2
    // re3 im3
    // re4 im4
    // re5 im5
    // re6 im6
    // re7 im7
    let inp0 = _mm_loadu_pd(inp.add(i) as _);
    let inp1 = _mm_loadu_pd(inp.add(i + 1) as _);
    let inp2 = _mm_loadu_pd(inp.add(i + 2) as _);
    let inp3 = _mm_loadu_pd(inp.add(i + 3) as _);
    let inp4 = _mm_loadu_pd(inp.add(i + 4) as _);
    let inp5 = _mm_loadu_pd(inp.add(i + 5) as _);
    let inp6 = _mm_loadu_pd(inp.add(i + 6) as _);
    let inp7 = _mm_loadu_pd(inp.add(i + 7) as _);

    let inp_re01 = _mm_unpacklo_pd(inp0, inp1);
    let inp_im01 = _mm_unpackhi_pd(inp0, inp1);
    let inp_re23 = _mm_unpacklo_pd(inp2, inp3);
    let inp_im23 = _mm_unpackhi_pd(inp2, inp3);
    let inp_re45 = _mm_unpacklo_pd(inp4, inp5);
    let inp_im45 = _mm_unpackhi_pd(inp4, inp5);
    let inp_re67 = _mm_unpacklo_pd(inp6, inp7);
    let inp_im67 = _mm_unpackhi_pd(inp6, inp7);

    let inp_re0123 = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_re01), inp_re23);
    let inp_im0123 = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_im01), inp_im23);
    let inp_re4567 = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_re45), inp_re67);
    let inp_im4567 = _mm256_insertf128_pd::<0b1>(_mm256_castpd128_pd256(inp_im45), inp_im67);

    let cast = _mm512_castpd256_pd512;

    let inp_re = _mm512_shuffle_f64x2::<0b01000100>(cast(inp_re0123), cast(inp_re4567));
    let inp_im = _mm512_shuffle_f64x2::<0b01000100>(cast(inp_im0123), cast(inp_im4567));

    let mul_re = _mm512_fmadd_pd(inp_re, w_re, _mm512_mul_pd(inp_im, w_im));
    let mul_im = _mm512_fnmadd_pd(inp_re, w_im, _mm512_mul_pd(inp_im, w_re));

    const ROUNDING: i32 = _MM_FROUND_TO_NEAREST_INT;

    let fract_re = _mm512_sub_pd(mul_re, _mm512_roundscale_pd::<ROUNDING>(mul_re));
    let fract_im = _mm512_sub_pd(mul_im, _mm512_roundscale_pd::<ROUNDING>(mul_im));
    let fract_re = _mm512_roundscale_pd::<ROUNDING>(_mm512_mul_pd(scaling, fract_re));
    let fract_im = _mm512_roundscale_pd::<ROUNDING>(_mm512_mul_pd(scaling, fract_im));

    (fract_re, fract_im)
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(all(
    feature = "backend_fft_nightly_avx512",
    any(target_arch = "x86_64", target_arch = "x86")
))]
#[target_feature(enable = "avx512f")]
unsafe fn convert_add_backward_torus_u32_avx512f(
    out_re: &mut [MaybeUninit<u32>],
    out_im: &mut [MaybeUninit<u32>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let n = out_re.len();
    debug_assert_eq!(n % 8, 0);
    debug_assert_eq!(n, out_re.len());
    debug_assert_eq!(n, out_im.len());
    debug_assert_eq!(n, inp.len());
    debug_assert_eq!(n, twisties.re.len());
    debug_assert_eq!(n, twisties.im.len());

    let normalization = _mm512_set1_pd(1.0 / n as f64);
    let scaling = _mm512_set1_pd(2.0_f64.powi(u32::BITS as i32));
    let out_re = out_re.as_mut_ptr() as *mut u32;
    let out_im = out_im.as_mut_ptr() as *mut u32;
    let inp = inp.as_ptr();
    let w_re = twisties.re.as_ptr();
    let w_im = twisties.im.as_ptr();

    for i in 0..n / 8 {
        let i = i * 8;

        let (fract_re, fract_im) =
            convert_torus_prologue_avx512f(normalization, w_re, i, w_im, inp, scaling);

        let fract_re = _mm512_cvtpd_epi32(fract_re);
        let fract_im = _mm512_cvtpd_epi32(fract_im);
        _mm256_storeu_si256(
            out_re.add(i) as _,
            _mm256_add_epi32(fract_re, _mm256_loadu_si256(out_re.add(i) as _)),
        );
        _mm256_storeu_si256(
            out_im.add(i) as _,
            _mm256_add_epi32(fract_im, _mm256_loadu_si256(out_im.add(i) as _)),
        );
    }
}

/// See [`convert_add_backward_torus`].
///
/// # Safety
///
///  - Same preconditions as [`convert_add_backward_torus`].
unsafe fn convert_add_backward_torus_scalar<Scalar: UnsignedTorus>(
    out_re: &mut [MaybeUninit<Scalar>],
    out_im: &mut [MaybeUninit<Scalar>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let normalization = 1.0 / inp.len() as f64;
    izip!(out_re, out_im, inp, twisties.re, twisties.im).for_each(
        |(out_re, out_im, inp, w_re, w_im)| {
            let tmp = inp
                * (c64 {
                    re: *w_re,
                    im: -*w_im,
                } * normalization);

            let out_re = out_re.assume_init_mut();
            let out_im = out_im.assume_init_mut();

            *out_re = Scalar::wrapping_add(*out_re, Scalar::from_torus(tmp.re));
            *out_im = Scalar::wrapping_add(*out_im, Scalar::from_torus(tmp.im));
        },
    );
}

/// # Warning
///
/// This function is actually unsafe, but can't be marked as such since we need it to implement
/// `Fn(...)`, as there's no equivalent `unsafe Fn(...)` trait.
///
/// # Safety
///
/// - `out_re` and `out_im` must not hold any uninitialized values.
fn convert_add_backward_torus<Scalar: UnsignedTorus>(
    out_re: &mut [MaybeUninit<Scalar>],
    out_im: &mut [MaybeUninit<Scalar>],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if Scalar::BITS == 32 {
            #[allow(clippy::type_complexity)]
            let ptr_fn = || -> unsafe fn (
                &mut [MaybeUninit<u32>],
                &mut [MaybeUninit<u32>],
                &[c64],
                TwistiesView<'_>,
            ) {
                #[cfg(feature = "backend_fft_nightly_avx512")]
                if is_x86_feature_detected!("avx512f") {
                    return convert_add_backward_torus_u32_avx512f;
                }

                if is_x86_feature_detected!("fma") {
                    convert_add_backward_torus_u32_fma
                } else {
                    convert_add_backward_torus_scalar::<u32>
                }
            };
            let ptr = ptr_fn();

            // SAFETY: the target x86 feature availability was checked, and `out_re` and `out_im`
            // do not hold any uninitialized values since that is a precondition of calling this
            // function
            unsafe {
                ptr(
                    cast_same_type(out_re),
                    cast_same_type(out_im),
                    inp,
                    twisties,
                )
            }
        } else {
            let ptr = convert_add_backward_torus_scalar::<Scalar>;
            // SAFETY: same as above
            unsafe { ptr(out_re, out_im, inp, twisties) };
        }
    }

    // SAFETY: same as above
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    unsafe {
        convert_add_backward_torus_scalar::<Scalar>(out_re, out_im, inp, twisties)
    };
}

impl<'a> FftView<'a> {
    /// Returns the polynomial size that this FFT was made for.
    pub fn polynomial_size(self) -> PolynomialSize {
        PolynomialSize(2 * self.plan.fft_size())
    }

    /// Serializes data in the Fourier domain.
    #[cfg(feature = "backend_fft_serialization")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backend_fft_serialization")))]
    pub fn serialize_fourier_buffer<S: serde::Serializer>(
        self,
        serializer: S,
        buf: &[c64],
    ) -> Result<S::Ok, S::Error> {
        self.plan.serialize_fourier_buffer(serializer, buf)
    }

    /// Deserializes data in the Fourier domain
    #[cfg(feature = "backend_fft_serialization")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backend_fft_serialization")))]
    pub fn deserialize_fourier_buffer<'de, D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
        buf: &mut [c64],
    ) -> Result<(), D::Error> {
        self.plan.deserialize_fourier_buffer(deserializer, buf)
    }

    /// Returns the memory required for a forward negacyclic FFT.
    pub fn forward_scratch(self) -> Result<StackReq, SizeOverflow> {
        self.plan.fft_scratch()
    }

    /// Returns the memory required for a backward negacyclic FFT.
    pub fn backward_scratch(self) -> Result<StackReq, SizeOverflow> {
        self.plan
            .fft_scratch()?
            .try_and(StackReq::try_new_aligned::<c64>(
                self.polynomial_size().0 / 2,
                aligned_vec::CACHELINE_ALIGN,
            )?)
    }

    /// Performs a negacyclic real FFT of `standard`, viewed as torus elements, and stores the
    /// result in `fourier`.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out` in an initialized state.
    ///
    /// # Panics
    ///
    /// Panics if `standard` and `self` have differing polynomial sizes, or if `fourier` doesn't
    /// have size equal to that amount divided by two.
    pub fn forward_as_torus<'out, Scalar: UnsignedTorus>(
        self,
        fourier: FourierPolynomialUninitMutView<'out>,
        standard: PolynomialView<'_, Scalar>,
        stack: DynStack<'_>,
    ) -> FourierPolynomialMutView<'out> {
        // SAFETY: `convert_forward_torus` initializes the output slice that is passed to it
        unsafe { self.forward_with_conv(fourier, standard, convert_forward_torus, stack) }
    }

    /// Performs a negacyclic real FFT of `standard`, viewed as integers, and stores the result in
    /// `fourier`.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out` in an initialized state.
    ///
    /// # Panics
    ///
    /// Panics if `standard` and `self` have differing polynomial sizes, or if `fourier` doesn't
    /// have size equal to that amount divided by two.
    pub fn forward_as_integer<'out, Scalar: UnsignedTorus>(
        self,
        fourier: FourierPolynomialUninitMutView<'out>,
        standard: PolynomialView<'_, Scalar>,
        stack: DynStack<'_>,
    ) -> FourierPolynomialMutView<'out> {
        // SAFETY: `convert_forward_integer` initializes the output slice that is passed to it
        unsafe { self.forward_with_conv(fourier, standard, convert_forward_integer, stack) }
    }

    /// Performs an inverse negacyclic real FFT of `fourier` and stores the result in `standard`,
    /// viewed as torus elements.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out_re` and `out_im` in an initialized state.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn backward_as_torus<'out, Scalar: UnsignedTorus>(
        self,
        standard: PolynomialUninitMutView<'out, Scalar>,
        fourier: FourierPolynomialView<'_>,
        stack: DynStack<'_>,
    ) -> PolynomialMutView<'out, Scalar> {
        // SAFETY: `convert_backward_torus` initializes the output slices that are passed to it
        unsafe { self.backward_with_conv(standard, fourier, convert_backward_torus, stack) }
    }

    /// Performs an inverse negacyclic real FFT of `fourier` and adds the result to `standard`,
    /// viewed as torus elements.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out_re` and `out_im` in an initialized state.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn add_backward_as_torus<'out, Scalar: UnsignedTorus>(
        self,
        standard: PolynomialMutView<'out, Scalar>,
        fourier: FourierPolynomialView<'_>,
        stack: DynStack<'_>,
    ) -> PolynomialMutView<'out, Scalar> {
        // SAFETY: `convert_add_backward_torus` initializes the output slices that are passed to it
        unsafe {
            self.backward_with_conv(
                standard.into_uninit(),
                fourier,
                convert_add_backward_torus,
                stack,
            )
        }
    }

    /// # Safety
    ///
    /// `conv_fn` must initialize the entirety of the mutable slice that it receives.
    unsafe fn forward_with_conv<
        'out,
        Scalar: UnsignedTorus,
        F: Fn(&mut [MaybeUninit<c64>], &[Scalar], &[Scalar], TwistiesView<'_>),
    >(
        self,
        fourier: FourierPolynomialUninitMutView<'out>,
        standard: PolynomialView<'_, Scalar>,
        conv_fn: F,
        stack: DynStack<'_>,
    ) -> FourierPolynomialMutView<'out> {
        let fourier = fourier.data;
        let standard = standard.data;
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier.len());
        let (standard_re, standard_im) = standard.split_at(n / 2);
        conv_fn(fourier, standard_re, standard_im, self.twisties);
        let fourier = assume_init_mut(fourier);
        self.plan.fwd(fourier, stack);
        FourierPolynomialMutView { data: fourier }
    }

    /// # Safety
    ///
    /// `conv_fn` must initialize the entirety of the mutable slices that it receives.
    unsafe fn backward_with_conv<
        'out,
        Scalar: UnsignedTorus,
        F: Fn(&mut [MaybeUninit<Scalar>], &mut [MaybeUninit<Scalar>], &[c64], TwistiesView<'_>),
    >(
        self,
        standard: PolynomialUninitMutView<'out, Scalar>,
        fourier: FourierPolynomialView<'_>,
        conv_fn: F,
        stack: DynStack<'_>,
    ) -> PolynomialMutView<'out, Scalar> {
        let fourier = fourier.data;
        let standard = standard.data;
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier.len());
        let (mut tmp, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier.iter().copied());
        self.plan.inv(&mut tmp, stack);

        let (standard_re, standard_im) = standard.split_at_mut(n / 2);
        conv_fn(standard_re, standard_im, &tmp, self.twisties);
        let standard = assume_init_mut(standard);
        PolynomialMutView { data: standard }
    }
}

#[cfg(test)]
mod tests;
