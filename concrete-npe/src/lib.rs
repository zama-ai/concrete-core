#![deny(rustdoc::broken_intra_doc_links)]
//! Welcome the the `concrete-npe` documentation!
//!
//! # Description
//! This library makes it possible to estimate the noise propagation after homomorphic operations.
//! It makes it possible to obtain characteristics of the output distribution of the noise, that we
//! call **dispersion**, which regroups the
//! variance and expectation. This is particularly useful to track the noise growth during the
//! homomorphic evaluation of a circuit. The explanations and the proofs of these formula can be
//! found in the appendices of the article [Improved Programmable Bootstrapping with Larger
//! Precision
//! and Efficient Arithmetic Circuits for TFHE]([https://eprint.iacr.org/2021/729]) by *Ilaria
//! Chillotti, Damien Ligier, Jean-Baptiste Orfila and Samuel Tap*.
//!
//! # Quick Example
//! The following piece of code shows how to obtain the variance $\sigma\_{add}$ of the noise
//! after a simulated homomorphic addition between two ciphertexts which have variances
//! $\sigma\_{ct\_1}$ and $\sigma\_{ct\_2}$, respectively.
//!
//! # Example:
//! ```rust
//! use concrete_core::prelude::{DispersionParameter, Variance};
//! use concrete_npe::estimate_addition_noise;
//! //We suppose that the two ciphertexts have the same variance.
//! let var1 = Variance(2_f64.powf(-25.));
//! let var2 = Variance(2_f64.powf(-25.));
//!
//! //We call the npe to estimate characteristics of the noise after an addition
//! //between these two variances.
//! //Here, we assume that ciphertexts are encoded over 64 bits.
//! let var_out = estimate_addition_noise::<_, _>(var1, var2, 64);
//! println!("Expect Variance (2^24) =  {}", 2_f64.powi(-24));
//! println!("Output Variance {}", var_out.get_variance());
//! assert!((2_f64.powi(-24) - var_out.get_variance()).abs() < 0.0001);
//! ```

#![allow(clippy::upper_case_acronyms)]

mod key_dispersion;
mod operators;
mod tools;

pub use key_dispersion::*;
pub use operators::*;
pub use tools::*;
