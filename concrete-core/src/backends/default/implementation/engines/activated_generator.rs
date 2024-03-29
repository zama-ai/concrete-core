#[cfg(feature = "backend_default_generator_x86_64_aesni")]
use concrete_csprng::generators::AesniRandomGenerator;
#[cfg(feature = "backend_default_generator_aarch64_aes")]
use concrete_csprng::generators::NeonAesRandomGenerator;
#[cfg(all(
    not(feature = "backend_default_generator_x86_64_aesni"),
    not(feature = "backend_default_generator_aarch64_aes")
))]
use concrete_csprng::generators::SoftwareRandomGenerator;

#[cfg(feature = "backend_default_generator_x86_64_aesni")]
pub type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(feature = "backend_default_generator_aarch64_aes")]
pub type ActivatedRandomGenerator = NeonAesRandomGenerator;
#[cfg(all(
    not(feature = "backend_default_generator_x86_64_aesni"),
    not(feature = "backend_default_generator_aarch64_aes")
))]
pub type ActivatedRandomGenerator = SoftwareRandomGenerator;
