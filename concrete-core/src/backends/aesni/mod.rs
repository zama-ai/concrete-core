//! A pure-rust backend that benefits from hardware acceleration
//! on x86_64 architectures with the aesni feature.

mod implementation;

pub use implementation::engines;
