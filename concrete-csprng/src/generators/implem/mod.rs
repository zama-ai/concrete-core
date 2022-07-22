#[cfg(feature = "generator_x86_64_aesni")]
mod aesni;
#[cfg(feature = "generator_x86_64_aesni")]
pub use aesni::*;

#[cfg(feature = "generator_aarch64_aes")]
mod aarch64;
#[cfg(feature = "generator_aarch64_aes")]
pub use aarch64::*;

#[cfg(feature = "generator_soft")]
mod soft;
#[cfg(feature = "generator_soft")]
pub use soft::*;
