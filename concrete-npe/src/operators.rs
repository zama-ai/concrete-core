use concrete_core::commons::numeric::{CastInto, UnsignedInteger};
use concrete_core::prelude::{
    BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, ExtractedBitsCount,
    GlweDimension, LweDimension, PolynomialSize,
};
/// Contains material needed to estimate the growth of the noise when performing homomorphic
/// computation
use concrete_core::prelude::{DispersionParameter, Variance};

use super::*;

/// Computes the dispersion of an addition of two
/// uncorrelated ciphertexts.
/// # Example:
/// ```rust
/// use concrete_core::prelude::{DispersionParameter, Variance};
/// use concrete_npe::estimate_addition_noise;
/// let var1 = Variance(2_f64.powf(-25.));
/// let var2 = Variance(2_f64.powf(-25.));
/// let var_out = estimate_addition_noise::<_, _>(var1, var2, 64);
/// println!("Expect Variance (2^24) =  {}", 2_f64.powi(-24));
/// println!("Output Variance {}", var_out.get_variance());
/// assert!((2_f64.powi(-24) - var_out.get_variance()).abs() < 0.0001);
/// ```
pub fn estimate_addition_noise<D1, D2>(
    dispersion_ct1: D1,
    dispersion_ct2: D2,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
{
    // The result variance is equal to the sum of the input variances
    let var_res: f64 = dispersion_ct1.get_modular_variance(log2_modulus)
        + dispersion_ct2.get_modular_variance(log2_modulus);
    Variance::from_modular_variance(var_res, log2_modulus)
}

/// Computes the dispersion of an addition of
/// several uncorrelated ciphertexts.
/// # Example:
/// ```rust
/// use concrete_core::prelude::{DispersionParameter, Variance};
/// use concrete_npe::estimate_several_additions_noise;
/// let var1 = Variance(2_f64.powf(-25.));
/// let var2 = Variance(2_f64.powf(-25.));
/// let var3 = Variance(2_f64.powf(-24.));
/// let var_in = [var1, var2, var3];
/// let var_out = estimate_several_additions_noise::<_>(&var_in, 64);
/// println!("Expect Variance (2^24) =  {}", 2_f64.powi(-23));
/// println!("Output Variance {}", var_out.get_variance());
/// assert!((2_f64.powi(-23) - var_out.get_variance()).abs() < 0.0001);
/// ```
pub fn estimate_several_additions_noise<D>(dispersion_cts: &[D], log2_modulus: u32) -> Variance
where
    D: DispersionParameter,
{
    let mut var_res: f64 = 0.;
    // The result variance is equal to the sum of the input variances
    for dispersion in dispersion_cts.iter() {
        var_res += dispersion.get_modular_variance(log2_modulus);
    }
    Variance::from_modular_variance(var_res, log2_modulus)
}

/// Computes the dispersion of a multiplication
/// of a ciphertext by a scalar.
/// # Example
/// ```rust
/// use concrete_core::prelude::Variance;
/// use concrete_npe::estimate_integer_plaintext_multiplication_noise;
/// let variance = Variance(2_f64.powi(-48));
/// let n: u64 = 543;
/// // noise computation
/// let var_out = estimate_integer_plaintext_multiplication_noise::<u64, _>(variance, n);
/// ```
pub fn estimate_integer_plaintext_multiplication_noise<T, D>(variance: D, n: T) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let sn = n.into_signed();
    let product: f64 = (sn * sn).cast_into();
    Variance::from_variance(variance.get_variance() * product)
}

/// Computes the dispersion of a multisum between
/// uncorrelated ciphertexts and scalar weights $w\_i$ i.e.,  $\sigma\_{out}^2 = \sum\_i w\_i^2 *
/// \sigma\_i^2$.
/// # Example
/// ```rust
/// use concrete_core::prelude::Variance;
/// use concrete_npe::estimate_weighted_sum_noise;
/// let variances = vec![Variance(2_f64.powi(-30)), Variance(2_f64.powi(-32))];
/// let weights: Vec<u64> = vec![20, 10];
/// let var_out = estimate_weighted_sum_noise(&variances, &weights);
/// ```
pub fn estimate_weighted_sum_noise<T, D>(dispersion_list: &[D], weights: &[T]) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let mut var_res: f64 = 0.;

    for (dispersion, &w) in dispersion_list.iter().zip(weights) {
        var_res += estimate_integer_plaintext_multiplication_noise(*dispersion, w).get_variance();
    }
    Variance::from_variance(var_res)
}

/// Computes the dispersion of a multiplication
/// between an RLWE ciphertext and a scalar polynomial.
/// # Example
/// ```rust
/// use concrete_core::prelude::{PolynomialSize, Variance};
/// use concrete_npe::estimate_polynomial_plaintext_multiplication_noise;
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rlwe = Variance(2_f64.powi(-40));
/// let scalar_polynomial = vec![10, 15, 18];
/// let var_out = estimate_polynomial_plaintext_multiplication_noise::<u64, _>(
///     dispersion_rlwe,
///     &scalar_polynomial,
/// );
/// ```
pub fn estimate_polynomial_plaintext_multiplication_noise<T, D>(
    dispersion: D,
    scalar_polynomial: &[T],
) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    estimate_weighted_sum_noise(
        &vec![dispersion; scalar_polynomial.len()],
        scalar_polynomial,
    )
}

/// Computes the dispersion of a tensor product between two independent
/// GLWEs given a set of parameters.
/// # Example:
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
///     PolynomialSize, Variance,
/// };
/// use concrete_npe::estimate_tensor_product_noise;
/// let dimension = GlweDimension(3);
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rlwe_0 = Variance::from_modular_variance(2_f64.powi(24), 64);
/// let dispersion_rlwe_1 = Variance::from_modular_variance(2_f64.powi(24), 64);
/// let delta_1 = 2_f64.powi(40);
/// let delta_2 = 2_f64.powi(42);
/// let max_msg_1 = 15.;
/// let max_msg_2 = 7.;
/// let var_out = estimate_tensor_product_noise::<_, _, BinaryKeyKind>(
///     polynomial_size,
///     dimension,
///     dispersion_rlwe_0,
///     dispersion_rlwe_1,
///     delta_1,
///     delta_2,
///     max_msg_1,
///     max_msg_2,
///     64,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn estimate_tensor_product_noise<D1, D2, K>(
    poly_size: PolynomialSize,
    rlwe_dimension: GlweDimension,
    dispersion_glwe1: D1,
    dispersion_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    // constants
    let big_n = poly_size.0 as f64;
    let k = rlwe_dimension.0 as f64;
    let delta = f64::min(delta_1, delta_2);
    let delta_square = square(delta);
    let q_square = 2_f64.powi((2 * log2_modulus) as i32);
    // #1
    let res_1 = big_n / delta_square
        * (dispersion_glwe1.get_modular_variance(log2_modulus)
            * square(delta_2)
            * square(max_msg_2)
            + dispersion_glwe2.get_modular_variance(log2_modulus)
                * square(delta_1)
                * square(max_msg_1)
            + dispersion_glwe1.get_modular_variance(log2_modulus)
                * dispersion_glwe2.get_modular_variance(log2_modulus));

    // #2
    let res_2 = (
        // 1ere parenthese
        (q_square - 1.) / 12.
            * (1.
                + k * big_n
                    * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
                + k * big_n * square(K::expectation_key_coefficient()))
            + k * big_n / 4.
                * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
            + 1. / 4. * square(1. + k * big_n * K::expectation_key_coefficient())
    ) * (
        // 2e parenthese
        dispersion_glwe1.get_modular_variance(log2_modulus)
            + dispersion_glwe2.get_modular_variance(log2_modulus)
    ) * big_n
        / delta_square;

    // #3
    let res_3 = 1. / 12.
        + k * big_n / (12. * delta_square)
            * ((delta_square - 1.)
                * (K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
                    + square(K::expectation_key_coefficient()))
                + 3. * K::variance_key_coefficient(log2_modulus)
                    .get_modular_variance(log2_modulus))
        + k * (k - 1.) * big_n / (24. * delta_square)
            * ((delta_square - 1.)
                * (K::variance_coefficient_in_polynomial_key_times_key(poly_size, log2_modulus)
                    .get_modular_variance(log2_modulus)
                    + K::square_expectation_mean_in_polynomial_key_times_key(poly_size))
                + 3. * K::variance_coefficient_in_polynomial_key_times_key(
                    poly_size,
                    log2_modulus,
                )
                .get_modular_variance(log2_modulus))
        + k * big_n / (24. * delta_square)
            * ((delta_square - 1.)
                * (K::variance_odd_coefficient_in_polynomial_key_squared(poly_size, log2_modulus)
                    .get_modular_variance(log2_modulus)
                    + K::variance_even_coefficient_in_polynomial_key_squared(
                        poly_size,
                        log2_modulus,
                    )
                    .get_modular_variance(log2_modulus)
                    + 2. * K::squared_expectation_mean_in_polynomial_key_squared(
                        poly_size,
                        log2_modulus,
                    ))
                + 3. * (K::variance_odd_coefficient_in_polynomial_key_squared(
                    poly_size,
                    log2_modulus,
                )
                .get_modular_variance(log2_modulus)
                    + K::variance_even_coefficient_in_polynomial_key_squared(
                        poly_size,
                        log2_modulus,
                    )
                    .get_modular_variance(log2_modulus)));

    Variance::from_modular_variance(res_2 + res_1 + res_3, log2_modulus)
}

/// Computes the dispersion of a GLWE after relinearization.
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
///     PolynomialSize, Variance,
/// };
/// use concrete_npe::estimate_relinearization_noise;
/// let dimension = GlweDimension(3);
/// let l_gadget = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rlk = Variance(2_f64.powi(-38));
/// let var_cmux = estimate_relinearization_noise::<_, BinaryKeyKind>(
///     polynomial_size,
///     dimension,
///     dispersion_rlk,
///     base_log,
///     l_gadget,
///     64,
/// );
/// ```
pub fn estimate_relinearization_noise<D, K>(
    poly_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    dispersion_rlk: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
) -> Variance
where
    D: DispersionParameter,
    K: KeyDispersion,
{
    // constants
    let big_n = poly_size.0 as f64;
    let k = glwe_dimension.0 as f64;
    let base = 2_f64.powi(base_log.0 as i32);
    let b2l = 2_f64.powi((2 * level.0) as i32);
    let q_square = 2_f64.powi((2 * log2_modulus) as i32);

    // first term
    let res_1 =
        k * (level.0 as f64) * big_n * dispersion_rlk.get_modular_variance(log2_modulus) * (k + 1.)
            / 2.
            * (square(base) + 2.)
            / 12.;

    // second term
    let res_2 = k * big_n / 2.
        * (q_square / (12. * b2l) - 1. / 12.)
        * ((k - 1.)
            * (K::variance_coefficient_in_polynomial_key_times_key(poly_size, log2_modulus)
                .get_modular_variance(log2_modulus)
                + K::square_expectation_mean_in_polynomial_key_times_key(poly_size))
            + K::variance_odd_coefficient_in_polynomial_key_squared(poly_size, log2_modulus)
                .get_modular_variance(log2_modulus)
            + K::variance_even_coefficient_in_polynomial_key_squared(poly_size, log2_modulus)
                .get_modular_variance(log2_modulus)
            + 2. * K::square_expectation_mean_in_polynomial_key_times_key(poly_size));

    // third term
    let res_3 = k * big_n / 8.
        * ((k - 1.)
            * K::variance_coefficient_in_polynomial_key_times_key(poly_size, log2_modulus)
                .get_modular_variance(log2_modulus)
            + K::variance_odd_coefficient_in_polynomial_key_squared(poly_size, log2_modulus)
                .get_modular_variance(log2_modulus)
            + K::variance_even_coefficient_in_polynomial_key_squared(poly_size, log2_modulus)
                .get_modular_variance(log2_modulus));

    Variance::from_modular_variance(res_1 + res_2 + res_3, log2_modulus)
}

/// Computes the dispersion of a GLWE multiplication between two GLWEs (i.e., a
/// tensor product followed by a relinearization).
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
///     PolynomialSize, Variance,
/// };
/// use concrete_npe::estimate_multiplication_noise;
/// let dimension = GlweDimension(3);
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rlwe_0 = Variance::from_modular_variance(2_f64.powi(24), 64);
/// let dispersion_rlwe_1 = Variance::from_modular_variance(2_f64.powi(24), 64);
/// let delta_1 = 2_f64.powi(40);
/// let delta_2 = 2_f64.powi(42);
/// let max_msg_1 = 15.;
/// let max_msg_2 = 7.;
/// let l_gadget = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_rlk = Variance(2_f64.powi(-38));
/// let var_out = estimate_multiplication_noise::<_, _, _, BinaryKeyKind>(
///     polynomial_size,
///     dimension,
///     dispersion_rlwe_0,
///     dispersion_rlwe_1,
///     delta_1,
///     delta_2,
///     max_msg_1,
///     max_msg_2,
///     dispersion_rlk,
///     base_log,
///     l_gadget,
///     64,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn estimate_multiplication_noise<D1, D2, D3, K>(
    poly_size: PolynomialSize,
    mask_size: GlweDimension,
    dispersion_glwe1: D1,
    dispersion_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
    dispersion_rlk: D3,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K: KeyDispersion,
{
    // res 1
    let res_1: Variance = estimate_tensor_product_noise::<_, _, K>(
        poly_size,
        mask_size,
        dispersion_glwe1,
        dispersion_glwe2,
        delta_1,
        delta_2,
        max_msg_1,
        max_msg_2,
        log2_modulus,
    );

    // res 2
    let res_2: Variance = estimate_relinearization_noise::<_, K>(
        poly_size,
        mask_size,
        dispersion_rlk,
        base_log,
        level,
        log2_modulus,
    );

    Variance::from_modular_variance(
        res_1.get_modular_variance(log2_modulus) + res_2.get_modular_variance(log2_modulus),
        log2_modulus,
    )
}

/// Computes the dispersion of a modulus switching of an LWE encrypted with binary keys.
/// # Example
/// ```rust
/// use concrete_core::prelude::{LweDimension, Variance};
/// use concrete_npe::estimate_modulus_switching_noise_with_binary_key;
/// let lwe_mask_size = LweDimension(630);
/// let number_of_most_significant_bit: usize = 4;
/// let dispersion_input = Variance(2_f64.powi(-40));
/// let var_out = estimate_modulus_switching_noise_with_binary_key::<_>(
///     lwe_mask_size,
///     number_of_most_significant_bit,
///     dispersion_input,
///     64,
/// );
/// ```
pub fn estimate_modulus_switching_noise_with_binary_key<D>(
    lwe_mask_size: LweDimension,
    nb_msb: usize,
    var_in: D,
    log2_modulus: u32,
) -> Variance
where
    D: DispersionParameter,
{
    let w = 2_f64.powi(nb_msb as i32);
    let n = lwe_mask_size.0 as f64;
    let q_square = 2_f64.powi((2 * log2_modulus) as i32);
    Variance::from_modular_variance(
        var_in.get_modular_variance(log2_modulus) + 1. / 12. * q_square / square(w) - 1. / 12.
            + n / 24. * q_square / square(w)
            + n / 48.,
        log2_modulus,
    )
}

/// Computes the dispersion of the constant terms of a GLWE after an LWE
/// to GLWE keyswitch.
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance,
/// };
/// use concrete_npe::estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms;
/// let lwe_mask_size = LweDimension(630);
/// let l_ks = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_lwe = Variance(2_f64.powi(-38));
/// let dispersion_ks = Variance(2_f64.powi(-40));
/// let var_ks = estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<_, _, BinaryKeyKind>(
///     lwe_mask_size,
///     dispersion_lwe,
///     dispersion_ks,
///     base_log,
///     l_ks,
///     64,
/// );
/// ```
pub fn estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms<D1, D2, K>(
    lwe_mask_size: LweDimension,
    dispersion_lwe: D1,
    dispersion_ksk: D2,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    let n = lwe_mask_size.0 as f64;
    let base = 2_f64.powi(base_log.0 as i32);
    let b2l = 2_f64.powi((base_log.0 * 2 * level.0) as i32);
    let q_square = 2_f64.powi((2 * log2_modulus) as i32);

    // res 1
    let res_1 = dispersion_lwe.get_modular_variance(log2_modulus);

    // res 2
    let res_2 = n
        * (q_square / (12. * b2l) - 1. / 12.)
        * (K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
            + square(K::expectation_key_coefficient()));

    // res 3
    let res_3 =
        n / 4. * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus);

    // res 4
    let res_4 = n
        * (level.0 as f64)
        * dispersion_ksk.get_modular_variance(log2_modulus)
        * (square(base) + 2.)
        / 12.;

    Variance::from_modular_variance(res_1 + res_2 + res_3 + res_4, log2_modulus)
}

/// Computes the dispersion of the constant terms of a GLWE after an LWE
/// to GLWE private functional keyswitch.
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance,
/// };
/// use concrete_npe::estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms;
/// let lwe_mask_size = LweDimension(630);
/// let l_ks = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_lwe = Variance(2_f64.powi(-38));
/// let dispersion_ks = Variance(2_f64.powi(-40));
/// let function_lipschitz_bound = 10.;
/// let var_ks = estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
///     _,
///     _,
///     BinaryKeyKind,
/// >(
///     lwe_mask_size,
///     dispersion_lwe,
///     dispersion_ks,
///     base_log,
///     l_ks,
///     function_lipschitz_bound,
///     64,
/// );
/// ```
pub fn estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms<D1, D2, K>(
    lwe_mask_size: LweDimension,
    dispersion_lwe: D1,
    dispersion_ksk: D2,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    function_lipschitz_bound: f64,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    let n = lwe_mask_size.0 as f64;
    let base = 2_f64.powi(base_log.0 as i32);
    let b2l = 2_f64.powi((base_log.0 * 2 * level.0) as i32);
    let q_square = 2_f64.powi((2 * log2_modulus) as i32);
    let r2 = square(function_lipschitz_bound);

    // res 1
    let res_1 = r2 * dispersion_lwe.get_modular_variance(log2_modulus);

    // res 2
    let res_2 = r2
        * n
        * (q_square / (12. * b2l) - 1. / 12.)
        * (K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
            + square(K::expectation_key_coefficient()));

    // res 3
    let res_3 =
        r2 * n / 4. * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus);

    // res 4
    let res_4 = r2 * (q_square / (12. * b2l) - 1. / 12.);

    // res 5
    let res_5 = (n + 1.)
        * (level.0 as f64)
        * dispersion_ksk.get_modular_variance(log2_modulus)
        * (square(base) + 2.)
        / 12.;

    Variance::from_modular_variance(res_1 + res_2 + res_3 + res_4 + res_5, log2_modulus)
}

/// Computes the dispersion of the non-constant GLWE terms after an LWE to GLWE keyswitch.
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance,
/// };
/// use concrete_npe::estimate_keyswitch_noise_lwe_to_glwe_with_non_constant_terms;
/// let lwe_mask_size = LweDimension(630);
/// let l_ks = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_ks = Variance(2_f64.powi(-40));
/// // Compute the noise
/// let var_ks = estimate_keyswitch_noise_lwe_to_glwe_with_non_constant_terms::<_>(
///     lwe_mask_size,
///     dispersion_ks,
///     base_log,
///     l_ks,
///     64,
/// );
/// ```
pub fn estimate_keyswitch_noise_lwe_to_glwe_with_non_constant_terms<D>(
    lwe_mask_size: LweDimension,
    dispersion_ksk: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
) -> Variance
where
    D: DispersionParameter,
{
    let n = lwe_mask_size.0 as f64;
    let square_base = 2_f64.powi(2 * base_log.0 as i32);

    let res = n
        * (level.0 as f64)
        * dispersion_ksk.get_modular_variance(log2_modulus)
        * (square_base + 2.)
        / 12.;

    Variance::from_modular_variance(res, log2_modulus)
}

/// Computes the dispersion of the bits greater than $q$ after a modulus switching.
/// # Example
/// ```rust
/// use concrete_core::prelude::{BinaryKeyKind, PolynomialSize, Variance};
/// use concrete_npe::estimate_msb_noise_rlwe;
/// use std::fmt::Binary;
/// let rlwe_mask_size = PolynomialSize(1024);
/// let var_out = estimate_msb_noise_rlwe::<BinaryKeyKind>(rlwe_mask_size, 64);
/// ```
pub fn estimate_msb_noise_rlwe<K>(poly_size: PolynomialSize, log2_modulus: u32) -> Variance
where
    K: KeyDispersion,
{
    let q_square = 2_f64.powi((2 * log2_modulus) as i32);

    Variance::from_modular_variance(
        1. / q_square
            * ((q_square - 1.) / 12.
                * (1.
                    + (poly_size.0 as f64)
                        * K::variance_key_coefficient(log2_modulus)
                            .get_modular_variance(log2_modulus)
                    + (poly_size.0 as f64) * square(K::expectation_key_coefficient()))
                + (poly_size.0 as f64) / 4.
                    * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)),
        log2_modulus,
    )
}

/// Computes the dispersion of an external product (between and RLWE and a GGSW)
/// encrypting a binary keys (i.e., as in TFHE PBS).
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
///     PolynomialSize, Variance,
/// };
/// use concrete_npe::estimate_external_product_noise_with_binary_ggsw;
/// let poly_size = PolynomialSize(1024);
/// let mask_size = GlweDimension(2);
/// let level = DecompositionLevelCount(4);
/// let dispersion_rlwe = Variance(2_f64.powi(-40));
/// let dispersion_rgsw = Variance(2_f64.powi(-40));
/// let base_log = DecompositionBaseLog(7);
/// let var_ks = estimate_external_product_noise_with_binary_ggsw::<_, _, BinaryKeyKind>(
///     poly_size,
///     mask_size,
///     dispersion_rlwe,
///     dispersion_rgsw,
///     base_log,
///     level,
///     64,
/// );
/// ```
pub fn estimate_external_product_noise_with_binary_ggsw<D1, D2, K>(
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    var_glwe: D1,
    var_ggsw: D2,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    let l = level.0 as f64;
    let k = rlwe_mask_size.0 as f64;
    let big_n = poly_size.0 as f64;
    let b = 2_f64.powi(base_log.0 as i32);
    let b2l = 2_f64.powi((base_log.0 * 2 * level.0) as i32);
    let q_square = 2_f64.powi(2 * log2_modulus as i32);

    let res_1 =
        l * (k + 1.) * big_n * var_ggsw.get_modular_variance(log2_modulus) * (square(b) + 2.) / 12.;
    let res_2 = var_glwe.get_modular_variance(log2_modulus) / 2.;
    let res_3 = (q_square - b2l) / (24. * b2l)
        * (1.
            + k * big_n
                * (K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
                    + square(K::expectation_key_coefficient())));
    let res_4 = k * big_n / 8.
        * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus);
    let res_5 = 1. / 16. * square(1. - k * big_n * K::expectation_key_coefficient());
    Variance::from_modular_variance(res_1 + res_2 + res_3 + res_4 + res_5, log2_modulus)
}

/// Computes the dispersion of a CMUX controlled with a GGSW encrypting binary keys.
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, DispersionParameter,
///     GlweDimension, PolynomialSize, Variance,
/// };
/// use concrete_npe::estimate_cmux_noise_with_binary_ggsw;
/// let dimension = GlweDimension(3);
/// let l_gadget = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rgsw = Variance::from_modular_variance(2_f64.powi(26), 64);
/// let dispersion_rlwe_0 = Variance::from_modular_variance(2_f64.powi(25), 64);
/// let dispersion_rlwe_1 = Variance::from_modular_variance(2_f64.powi(25), 64);
/// // Compute the noise
/// let var_cmux = estimate_cmux_noise_with_binary_ggsw::<_, _, _, BinaryKeyKind>(
///     dimension,
///     polynomial_size,
///     base_log,
///     l_gadget,
///     dispersion_rlwe_0,
///     dispersion_rlwe_1,
///     dispersion_rgsw,
///     64,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn estimate_cmux_noise_with_binary_ggsw<D1, D2, D3, K>(
    dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    dispersion_rlwe_0: D1,
    dispersion_rlwe_1: D2,
    dispersion_rgsw: D3,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K: KeyDispersion,
{
    let var_external_product = estimate_external_product_noise_with_binary_ggsw::<_, _, K>(
        polynomial_size,
        dimension,
        estimate_addition_noise::<_, _>(dispersion_rlwe_0, dispersion_rlwe_1, log2_modulus),
        dispersion_rgsw,
        base_log,
        l_gadget,
        log2_modulus,
    );
    estimate_addition_noise::<_, _>(var_external_product, dispersion_rlwe_0, log2_modulus)
}

/// Computes the dispersion of a PBS *a la TFHE* (i.e., the GGSW encrypts a
/// binary keys, and the initial noise for the RLWE is equal to zero).
/// # Example
/// ```rust
/// use concrete_core::prelude::{
///     BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
///     PolynomialSize, Variance,
/// };
/// use concrete_npe::estimate_pbs_noise;
/// let poly_size = PolynomialSize(1024);
/// let mask_size = LweDimension(2);
/// let rlwe_mask_size = GlweDimension(2);
/// let level = DecompositionLevelCount(4);
/// let dispersion_rgsw = Variance(2_f64.powi(-40));
/// let base_log = DecompositionBaseLog(7);
/// let var_ks = estimate_pbs_noise::<_, BinaryKeyKind>(
///     mask_size,
///     poly_size,
///     rlwe_mask_size,
///     base_log,
///     level,
///     dispersion_rgsw,
///     64,
/// );
/// ```
pub fn estimate_pbs_noise<D, K>(
    lwe_mask_size: LweDimension,
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    dispersion_bsk: D,
    log2_modulus: u32,
) -> Variance
where
    D: DispersionParameter,
    K: KeyDispersion,
{
    let n = lwe_mask_size.0 as f64;
    let k = rlwe_mask_size.0 as f64;
    let b = 2_f64.powi(base_log.0 as i32);
    let b2l = 2_f64.powi((base_log.0 * 2 * level.0) as i32);
    let l = level.0 as f64;
    let big_n = poly_size.0 as f64;
    let q_square = 2_f64.powi(2 * log2_modulus as i32);

    let res_1 = n * l * (k + 1.) * big_n * (square(b) + 2.) / 12.
        * dispersion_bsk.get_modular_variance(log2_modulus);
    let res_2 = n * (q_square - b2l) / (24. * b2l)
        * (1.
            + k * big_n
                * (K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
                    + square(K::expectation_key_coefficient())))
        + n * k * big_n / 8.
            * K::variance_key_coefficient(log2_modulus).get_modular_variance(log2_modulus)
        + n / 16. * square(1. - k * big_n * K::expectation_key_coefficient());
    Variance::from_modular_variance(res_1 + res_2, log2_modulus)
}

/// Computes the dispersions of ciphertexts encrypting the bits after bit extraction, the
/// dispersion of the ciphertext of the most significant bit extracted is first and of the least
/// significant bit last.
/// # Example
/// ```rust
/// use concrete_core::prelude::*;
/// use concrete_npe::estimate_bit_extraction_noise;
/// let poly_size = PolynomialSize(1024);
/// let input_lwe_mask_size = LweDimension(667);
/// let lwe_mask_size_after_ks = LweDimension(512);
/// let glwe_mask_size = GlweDimension(2);
/// let dispersion_lwe = Variance(2_f64.powi(-38));
/// let dispersion_ksk = Variance(2_f64.powi(-31));
/// let dispersion_bsk = Variance(2_f64.powi(-104));
/// let level_ksk = DecompositionLevelCount(14);
/// let base_log_ksk = DecompositionBaseLog(1);
/// let level_bsk = DecompositionLevelCount(6);
/// let base_log_bsk = DecompositionBaseLog(7);
/// let number_of_bits_to_extract = ExtractedBitsCount(8);
/// let total_precision = 16_u32;
/// let vars_bit_extract = estimate_bit_extraction_noise::<_, _, _, BinaryKeyKind, BinaryKeyKind>(
///     number_of_bits_to_extract,
///     total_precision,
///     input_lwe_mask_size,
///     lwe_mask_size_after_ks,
///     glwe_mask_size,
///     poly_size,
///     dispersion_lwe,
///     dispersion_ksk,
///     dispersion_bsk,
///     base_log_ksk,
///     level_ksk,
///     base_log_bsk,
///     level_bsk,
///     64,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn estimate_bit_extraction_noise<D1, D2, D3, K1, K2>(
    number_of_bits_to_extract: ExtractedBitsCount,
    total_precision: u32,
    input_lwe_mask_size: LweDimension,
    lwe_mask_size_after_ks: LweDimension,
    glwe_mask_size: GlweDimension,
    poly_size: PolynomialSize,
    dispersion_lwe: D1,
    dispersion_ksk: D2,
    dispersion_bsk: D3,
    base_log_ksk: DecompositionBaseLog,
    level_ksk: DecompositionLevelCount,
    base_log_bsk: DecompositionBaseLog,
    level_bsk: DecompositionLevelCount,
    log2_modulus: u32,
) -> Vec<Variance>
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K1: KeyDispersion,
    K2: KeyDispersion,
{
    let mut loop_dispersions: Vec<Variance> = vec![Variance(0f64); number_of_bits_to_extract.0];
    let initial_var = dispersion_lwe.get_modular_variance(log2_modulus);
    loop_dispersions[0] = Variance::from_modular_variance(initial_var, log2_modulus);
    let mut output_dispersions: Vec<Variance> = vec![];
    for bit in 0..number_of_bits_to_extract.0 {
        let var_after_scaling: f64 = loop_dispersions[bit].get_modular_variance(log2_modulus)
            * 4_f64.powi((total_precision as i32) - (bit as i32) - 1);
        let dispersion_after_scaling =
            Variance::from_modular_variance(var_after_scaling, log2_modulus);
        let output_dispersion = estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<_, D2, K1>(
            input_lwe_mask_size,
            dispersion_after_scaling,
            dispersion_ksk,
            base_log_ksk,
            level_ksk,
            log2_modulus,
        );
        output_dispersions.push(output_dispersion);
        if bit != number_of_bits_to_extract.0 - 1 {
            let dispersion_after_pbs = estimate_pbs_noise::<D3, K2>(
                lwe_mask_size_after_ks,
                poly_size,
                glwe_mask_size,
                base_log_bsk,
                level_bsk,
                dispersion_bsk,
                log2_modulus,
            );
            loop_dispersions[bit + 1] = estimate_addition_noise::<_, _>(
                loop_dispersions[bit],
                dispersion_after_pbs,
                log2_modulus,
            );
        }
    }
    output_dispersions.reverse();
    output_dispersions
}

/// Computes the dispersion of a circuit bootstrapping for a binary message and a binary secret
/// key, each ciphertext output is the result of a PBS followed by a private functional
/// keyswitch where the private function is "multiplication by x" where `x` is one component
/// of a GLWE secret key, hence a polynomial with binary coefficients, or is the identity function.
///
/// # Example
/// ```rust
/// use concrete_core::prelude::*;
/// use concrete_npe::estimate_circuit_bootstrapping_binary_noise;
/// let lwe_mask_size = LweDimension(667);
/// let glwe_mask_size = GlweDimension(2);
/// let poly_size = PolynomialSize(1024);
/// let base_log = DecompositionBaseLog(4);
/// let level = DecompositionLevelCount(7);
/// let dispersion_bsk = Variance(2_f64.powi(-104));
/// let dispersion_ksk = Variance(2_f64.powi(-31));
/// let var_cb = estimate_circuit_bootstrapping_binary_noise::<_, _, BinaryKeyKind, BinaryKeyKind>(
///     lwe_mask_size,
///     poly_size,
///     glwe_mask_size,
///     base_log,
///     level,
///     dispersion_bsk,
///     dispersion_ksk,
///     64,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn estimate_circuit_bootstrapping_binary_noise<D1, D2, K1, K2>(
    lwe_mask_size: LweDimension,
    poly_size: PolynomialSize,
    glwe_mask_size: GlweDimension,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    dispersion_bsk: D1,
    dispersion_ksk: D2,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    K1: KeyDispersion,
    K2: KeyDispersion,
{
    estimate_private_functional_keyswitch_noise_lwe_to_glwe_with_constant_terms::<_, D2, K2>(
        LweDimension(glwe_mask_size.0 * poly_size.0),
        estimate_pbs_noise::<D1, K1>(
            lwe_mask_size,
            poly_size,
            glwe_mask_size,
            base_log,
            level,
            dispersion_bsk,
            log2_modulus,
        ),
        dispersion_ksk,
        base_log,
        level,
        1_f64, // Binary (or ternary) keys mean the lipschitz bound is 1
        log2_modulus,
    )
}

/// Compute the dispersion after a vertical packing. The output ciphertext is the result
/// of n sequential CMUX operations where n is the number of GGSW ciphertexts given.
/// During a PBS the final blind rotation also performs n sequential CMUX operations so we can
/// use the same noise estimation formula.
/// # Example
/// ```rust
/// use concrete_core::prelude::*;
/// use concrete_npe::estimate_vertical_packing_noise;
/// let poly_size = PolynomialSize(1024);
/// let glwe_mask_size = GlweDimension(2);
/// let base_log = DecompositionBaseLog(4);
/// let level = DecompositionLevelCount(7);
/// let dispersion_ggsw = Variance(2_f64.powi(-40));
/// let number_of_ggsw = 8;
/// let var_vp = estimate_vertical_packing_noise::<_>(
///     number_of_ggsw,
///     poly_size,
///     glwe_mask_size,
///     base_log,
///     level,
///     dispersion_ggsw,
///     64,
/// );
/// ```
pub fn estimate_vertical_packing_noise<D>(
    number_of_ggsw: usize,
    poly_size: PolynomialSize,
    glwe_mask_size: GlweDimension,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    dispersion_ggsw: D,
    log2_modulus: u32,
) -> Variance
where
    D: DispersionParameter,
{
    let n = LweDimension(number_of_ggsw);
    // BinaryKeyKind used as the GGSWs encrypt binary messages
    estimate_pbs_noise::<_, BinaryKeyKind>(
        n,
        poly_size,
        glwe_mask_size,
        base_log,
        level,
        dispersion_ggsw,
        log2_modulus,
    )
}

/// Compute the dispersion after a WoP-PBS.
///
/// # Example
/// ```rust
/// use concrete_core::prelude::*;
/// use concrete_npe::estimate_wop_pbs_noise;
/// let number_of_bits_to_extract = ExtractedBitsCount(8);
/// let lwe_mask_size = LweDimension(667);
/// let poly_size = PolynomialSize(1024);
/// let glwe_mask_size = GlweDimension(2);
/// let base_log_cb = DecompositionBaseLog(4);
/// let level_cb = DecompositionLevelCount(7);
/// let dispersion_cb_bsk = Variance(2_f64.powi(-104));
/// let dispersion_cb_pfksk = Variance(2_f64.powi(-31));
/// let var_wop_pbs = estimate_wop_pbs_noise::<_, _, BinaryKeyKind, BinaryKeyKind>(
///     number_of_bits_to_extract,
///     lwe_mask_size,
///     poly_size,
///     glwe_mask_size,
///     base_log_cb,
///     level_cb,
///     dispersion_cb_bsk,
///     dispersion_cb_pfksk,
///     64,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn estimate_wop_pbs_noise<D1, D2, K1, K2>(
    number_of_bits_to_extract: ExtractedBitsCount,
    lwe_mask_size_after_bit_extraction: LweDimension,
    poly_size: PolynomialSize,
    glwe_mask_size: GlweDimension,
    base_log_cb: DecompositionBaseLog,
    level_cb: DecompositionLevelCount,
    dispersion_cb_bsk: D1,
    dispersion_cb_pfksk: D2,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
    D2: DispersionParameter,
    K1: KeyDispersion,
    K2: KeyDispersion,
{
    estimate_vertical_packing_noise::<_>(
        number_of_bits_to_extract.0,
        poly_size,
        glwe_mask_size,
        base_log_cb,
        level_cb,
        estimate_circuit_bootstrapping_binary_noise::<D1, D2, K1, K2>(
            lwe_mask_size_after_bit_extraction,
            poly_size,
            glwe_mask_size,
            base_log_cb,
            level_cb,
            dispersion_cb_bsk,
            dispersion_cb_pfksk,
            log2_modulus,
        ),
        log2_modulus,
    )
}

#[cfg(test)]
mod tests_estimate_weighted_sum_noise {
    use super::estimate_weighted_sum_noise;
    use crate::tools::tests::assert_float_eq;
    use concrete_core::prelude::{DispersionParameter, Variance};
    #[test]
    fn no_noise() {
        let weights = [1u8, 1];
        let variance_in = [Variance(0.0), Variance(0.0)];
        let variance_out = estimate_weighted_sum_noise(&variance_in, &weights);
        assert_float_eq!(0.0, variance_out.get_variance(), eps = 0.0);
    }
    #[test]
    fn no_more_noise() {
        let weights = [1u8, 1, 1];
        let variance_in = [Variance(1.0), Variance(0.0)];
        let variance_out = estimate_weighted_sum_noise(&variance_in, &weights);
        assert_float_eq!(1.0, variance_out.get_variance(), eps = 0.0);
    }
    #[test]
    fn twice_the_noise() {
        let weights = [1u8, 1];
        let variance_in = [Variance(1.0), Variance(1.0)];
        let variance_out = estimate_weighted_sum_noise(&variance_in, &weights);
        assert_float_eq!(2.0, variance_out.get_variance(), eps = 0.0);
    }
    #[test]
    fn more_noise() {
        let weights = [1u8, 3];
        let variance_in = [Variance(2.0), Variance(5.0)];
        let variance_out = estimate_weighted_sum_noise(&variance_in, &weights);
        assert_float_eq!(47.0, variance_out.get_variance(), eps = 0.001);
    }
}
