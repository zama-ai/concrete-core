//! This trait contains functions related to the dispersion of secret key coefficients, and
//! operations related to the secret keys (e.g., products of secret keys).

use super::*;
use concrete_core::prelude::{PolynomialSize, *};

// The Gaussian secret keys have modular standard deviation set to 3.2 by default.
const GAUSSIAN_MODULAR_STDEV: f64 = 3.2;

/// This trait contains functions related to the dispersion of secret key coefficients, and
/// operations related to the secret keys (e.g., products of secret keys).
pub trait KeyDispersion: KeyKind {
    /// Returns the variance of key coefficients.
    /// # Example
    ///```rust
    /// use concrete_core::prelude::*;
    /// use concrete_npe::*;
    ///
    /// let var_out_1 =
    ///     Variance::get_modular_variance(&GaussianKeyKind::variance_key_coefficient(64), 64);
    /// let expected_var_out_1 = 10.24;
    /// println!("{}", var_out_1);
    /// assert!((expected_var_out_1 - var_out_1).abs() < 0.0001);
    /// ```
    fn variance_key_coefficient(log2_modulus: u32) -> Variance;

    /// Returns the expectation of key coefficients.
    /// # Example
    ///```rust
    /// use concrete_core::prelude::*;
    /// use concrete_npe::*;
    ///
    /// type ui = u64;
    ///
    /// let expect_out_1 = BinaryKeyKind::expectation_key_coefficient();
    /// let expected_expect_out_1 = 0.5;
    /// println!("{}", expect_out_1);
    /// assert!((expected_expect_out_1 - expect_out_1).abs() < 0.0001);
    /// ```
    fn expectation_key_coefficient() -> f64;

    /// Returns the variance of the squared key coefficients.
    /// # Example
    ///```rust
    /// use concrete_core::prelude::*;
    /// use concrete_npe::*;
    ///
    /// let var_out_2 =
    ///     Variance::get_modular_variance(&TernaryKeyKind::variance_key_coefficient_squared(64), 64);
    /// let expected_var_out_2 = 0.2222;
    /// println!("{}", var_out_2);
    /// assert!((expected_var_out_2 - var_out_2).abs() < 0.0001);
    /// ```
    fn variance_key_coefficient_squared(log2_modulus: u32) -> Variance;

    /// Returns the expectation of the squared key coefficients.
    /// # Example
    ///```rust
    /// use concrete_core::prelude::*;
    /// use concrete_npe::*;
    ///
    /// let expect_out_2 = GaussianKeyKind::expectation_key_coefficient_squared(64);
    /// let expected_expect_out_2 = 10.24;
    /// println!("{}", expect_out_2);
    /// assert!((expected_expect_out_2 - expect_out_2).abs() < 0.0001);
    /// ```
    fn expectation_key_coefficient_squared(log2_modulus: u32) -> f64;

    /// Returns the variance of the odd coefficients of a polynomial key to the square.
    /// # Example
    ///```rust
    /// use concrete_core::prelude::{PolynomialSize, *};
    /// use concrete_npe::*;
    ///
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// let var_odd_out_3 = Variance::get_modular_variance(
    ///     &TernaryKeyKind::variance_odd_coefficient_in_polynomial_key_squared(polynomial_size, 64),
    ///     64,
    /// );
    /// let expected_var_odd_out_3 = 910.2222;
    /// println!("{}", var_odd_out_3);
    /// assert!((expected_var_odd_out_3 - var_odd_out_3).abs() < 0.0001);
    /// ```
    fn variance_odd_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance;

    /// Returns the variance of the even coefficients of a polynomial key to the square
    /// # Example
    ///```rust
    /// use concrete_core::prelude::{PolynomialSize, *};
    /// use concrete_npe::*;
    ///
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// let var_even_out_3 = Variance::get_modular_variance(
    ///     &BinaryKeyKind::variance_even_coefficient_in_polynomial_key_squared(polynomial_size, 64),
    ///     64,
    /// );
    /// let expected_var_even_out_3 = 383.75;
    /// println!("{}", var_even_out_3);
    /// assert!((expected_var_even_out_3 - var_even_out_3).abs() < 0.0001);
    /// ```
    fn variance_even_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance;

    /// Returns the mean expectation of the coefficients of a polynomial key to the square.
    /// # Example
    ///```rust
    /// use concrete_core::prelude::{PolynomialSize, *};
    /// use concrete_npe::*;
    ///
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// let expect_out_3 =
    ///     GaussianKeyKind::squared_expectation_mean_in_polynomial_key_squared(polynomial_size, 64);
    /// let expected_expect_out_3 = 0.0;
    /// println!("{}", expect_out_3);
    /// assert!((expected_expect_out_3 - expect_out_3).abs() < 0.0001);
    /// ```
    fn squared_expectation_mean_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> f64;

    /// Returns the variance of the
    /// coefficients of a polynomial key resulting from the multiplication of two polynomial keys
    /// of the same key kind ($S\_i \cdot S\_j$ with $i,j$ different).
    /// # Example
    ///```rust
    /// use concrete_core::prelude::{PolynomialSize, *};
    /// use concrete_npe::*;
    ///
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// let var_out_4 = Variance::get_modular_variance(
    ///     &ZeroKeyKind::variance_coefficient_in_polynomial_key_times_key(polynomial_size, 64),
    ///     64,
    /// );
    /// let expected_var_out_4 = 0.0;
    /// println!("{}", var_out_4);
    /// assert!((expected_var_out_4 - var_out_4).abs() < 0.0001);
    /// ```
    fn variance_coefficient_in_polynomial_key_times_key(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance;

    /// Returns the mean expectation of
    /// the coefficients of a polynomial key resulting from the multiplication of two polynomial
    /// keys of the same key kind ($S\_i \cdot S\_j$ with $i,j$ different).
    /// # Example
    ///```rust
    /// use concrete_core::prelude::{PolynomialSize, *};
    /// use concrete_npe::*;
    ///
    /// type ui = u64;
    /// let polynomial_size = PolynomialSize(2048);
    ///
    /// let expect_out_4 =
    ///     BinaryKeyKind::square_expectation_mean_in_polynomial_key_times_key(polynomial_size);
    /// let expected_expect_out_4 = 87381.375;
    /// println!("{}", expect_out_4);
    /// assert!((expected_expect_out_4 - expect_out_4).abs() < 0.0001);
    /// ```
    fn square_expectation_mean_in_polynomial_key_times_key(poly_size: PolynomialSize) -> f64;
}

/// Implementations are provided for binary, ternary and Gaussian key kinds.
/// The ZeroKeyKind is only for debug purposes.
impl KeyDispersion for BinaryKeyKind {
    fn variance_key_coefficient(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(1. / 4., log2_modulus)
    }
    fn expectation_key_coefficient() -> f64 {
        1. / 2.
    }
    fn variance_key_coefficient_squared(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(1. / 4., log2_modulus)
    }
    fn expectation_key_coefficient_squared(_log2_modulus: u32) -> f64 {
        1. / 2.
    }
    fn variance_odd_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        if poly_size.0 == 1 {
            Variance::from_modular_variance(0., log2_modulus)
        } else {
            Variance::from_modular_variance(3. * (poly_size.0 as f64) / 8., log2_modulus)
        }
    }
    fn variance_even_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        if poly_size.0 == 1 {
            Variance::from_modular_variance(
                2. * Variance::get_modular_variance(
                    &BinaryKeyKind::variance_key_coefficient_squared(log2_modulus),
                    log2_modulus,
                ),
                log2_modulus,
            )
        } else {
            Variance::from_modular_variance(((3 * poly_size.0 - 2) as f64) / 8., log2_modulus)
        }
    }
    fn squared_expectation_mean_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> f64 {
        if poly_size.0 == 1 {
            square(BinaryKeyKind::expectation_key_coefficient_squared(
                log2_modulus,
            ))
        } else {
            (square(poly_size.0 as f64) + 2.) / 48.
        }
    }
    fn variance_coefficient_in_polynomial_key_times_key(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        Variance::from_modular_variance(3. * (poly_size.0 as f64) / 16., log2_modulus)
    }
    fn square_expectation_mean_in_polynomial_key_times_key(poly_size: PolynomialSize) -> f64 {
        (square(poly_size.0 as f64) + 2.) / 48.
    }
}

impl KeyDispersion for TernaryKeyKind {
    fn variance_key_coefficient(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(2. / 3., log2_modulus)
    }
    fn expectation_key_coefficient() -> f64 {
        0.
    }
    fn variance_key_coefficient_squared(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(2. / 9., log2_modulus)
    }
    fn expectation_key_coefficient_squared(_log2_modulus: u32) -> f64 {
        2. / 3.
    }
    fn variance_odd_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        if poly_size.0 == 1 {
            Variance::from_modular_variance(0., log2_modulus)
        } else {
            Variance::from_modular_variance(8. * (poly_size.0 as f64) / 9., log2_modulus)
        }
    }
    fn variance_even_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        if poly_size.0 == 1 {
            Variance::from_modular_variance(
                2. * Variance::get_modular_variance(
                    &TernaryKeyKind::variance_key_coefficient_squared(log2_modulus),
                    log2_modulus,
                ),
                log2_modulus,
            )
        } else {
            Variance::from_modular_variance(4. * ((2 * poly_size.0 - 3) as f64) / 9., log2_modulus)
        }
    }
    fn squared_expectation_mean_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> f64 {
        if poly_size.0 == 1 {
            square(TernaryKeyKind::expectation_key_coefficient_squared(
                log2_modulus,
            ))
        } else {
            0.
        }
    }
    fn variance_coefficient_in_polynomial_key_times_key(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        Variance::from_modular_variance(4. * (poly_size.0 as f64) / 9., log2_modulus)
    }
    fn square_expectation_mean_in_polynomial_key_times_key(_poly_size: PolynomialSize) -> f64 {
        0.
    }
}

impl KeyDispersion for GaussianKeyKind {
    fn variance_key_coefficient(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(square(GAUSSIAN_MODULAR_STDEV), log2_modulus)
    }
    fn expectation_key_coefficient() -> f64 {
        0.
    }
    fn variance_key_coefficient_squared(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(
            2. * square(Variance::get_modular_variance(
                &GaussianKeyKind::variance_key_coefficient(log2_modulus),
                log2_modulus,
            )),
            log2_modulus,
        )
    }
    fn expectation_key_coefficient_squared(log2_modulus: u32) -> f64 {
        Variance::get_modular_variance(
            &GaussianKeyKind::variance_key_coefficient(log2_modulus),
            log2_modulus,
        )
    }
    fn variance_odd_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        if poly_size.0 == 1 {
            Variance::from_modular_variance(0., log2_modulus)
        } else {
            Variance::from_modular_variance(
                2. * (poly_size.0 as f64)
                    * square(Variance::get_modular_variance(
                        &GaussianKeyKind::variance_key_coefficient(log2_modulus),
                        log2_modulus,
                    )),
                log2_modulus,
            )
        }
    }
    fn variance_even_coefficient_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        if poly_size.0 == 1 {
            Variance::from_modular_variance(
                2. * Variance::get_modular_variance(
                    &GaussianKeyKind::variance_key_coefficient_squared(log2_modulus),
                    log2_modulus,
                ),
                log2_modulus,
            )
        } else {
            Variance::from_modular_variance(
                2. * (poly_size.0 as f64)
                    * square(Variance::get_modular_variance(
                        &GaussianKeyKind::variance_key_coefficient(log2_modulus),
                        log2_modulus,
                    )),
                log2_modulus,
            )
        }
    }
    fn squared_expectation_mean_in_polynomial_key_squared(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> f64 {
        if poly_size.0 == 1 {
            square(GaussianKeyKind::expectation_key_coefficient_squared(
                log2_modulus,
            ))
        } else {
            0.
        }
    }
    fn variance_coefficient_in_polynomial_key_times_key(
        poly_size: PolynomialSize,
        log2_modulus: u32,
    ) -> Variance {
        Variance::from_modular_variance(
            square(Variance::get_modular_variance(
                &GaussianKeyKind::variance_key_coefficient(log2_modulus),
                log2_modulus,
            )) * (poly_size.0 as f64),
            log2_modulus,
        )
    }
    fn square_expectation_mean_in_polynomial_key_times_key(_poly_size: PolynomialSize) -> f64 {
        0.
    }
}

impl KeyDispersion for ZeroKeyKind {
    fn variance_key_coefficient(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(0., log2_modulus)
    }
    fn expectation_key_coefficient() -> f64 {
        0.
    }
    fn variance_key_coefficient_squared(log2_modulus: u32) -> Variance {
        Variance::from_modular_variance(0., log2_modulus)
    }
    fn expectation_key_coefficient_squared(_log2_modulus: u32) -> f64 {
        0.
    }
    fn variance_odd_coefficient_in_polynomial_key_squared(
        _poly_size: PolynomialSize,
        _log2_modulus: u32,
    ) -> Variance {
        Variance(0.)
    }
    fn variance_even_coefficient_in_polynomial_key_squared(
        _poly_size: PolynomialSize,
        _log2_modulus: u32,
    ) -> Variance {
        Variance(0.)
    }
    fn squared_expectation_mean_in_polynomial_key_squared(
        _poly_size: PolynomialSize,
        _log2_modulus: u32,
    ) -> f64 {
        0.
    }
    fn variance_coefficient_in_polynomial_key_times_key(
        _poly_size: PolynomialSize,
        _log2_modulus: u32,
    ) -> Variance {
        Variance(0.)
    }
    fn square_expectation_mean_in_polynomial_key_times_key(_poly_size: PolynomialSize) -> f64 {
        0.
    }
}
