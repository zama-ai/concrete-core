# Activating Backends

As mentioned in the [API structure page](../general\_concepts/api\_structure.md), four backends are currently available:

* The default backend: always activated at compile time. Unless configured otherwise, it does not contain any hardware-specific instructions. It is possible to configure it to activate x86\_64 or aarch64 specific acceleration for the encryption and creation of keys (with `aesni` and `rdseed` features on x86\_64 platforms, and with the Neon `aes` and the Enclave seeder on aarm64 platforms). It also implements engines that accelerate some operations with multithreading (for now, the bootstrap key creation only). Finally, it also implements engines dedicated to serialization. The corresponding features are:
  * `backend_default_generator_x86_64_aesni`
  * `backend_default_generator_aarch64_aes`
  * `backend_default_parallel`
  * `backend_default_serialization`
* The FFT backend: this backend implements engines that require an FFT implementation, and relies on an in-house FFT implementation for it. For example, such operations are the bootstrap, the external product and the Cmux. It also implements operations to perform a large precision bootstrap (up to 16 bits). It can be configured to activate serialization:
  * `backend_fft_serialization` The FFT implementation can also be accelerated via `avx512` instructions (for this, the nightly version of Rust is required), via the feature:
  * `backend_fft_nightly_avx512`
* The Cuda backend: this backend exposes two Cuda-accelerated implementations of the bootstrap, as well as a Cuda-accelerated keyswitch.

## Multithreaded use

In the general case, engines objects should not be expected to be thread-safe. That is, using them concurrently from different threads may lead to undefined behavior (this remark mainly applies to the case where `concrete-core` is used via its C API -- `concrete-core-ffi`).

The expected way to build on top of engines, is to expose them as thread-local global variables. That is, if we want to use a `default::DefaultEngine` object, we should use the following approach:

```rust
const UNSAFE_SECRET: u128 = 0;
thread_local! {
    pub static DEFAULT_ENGINE: RefCell<DefaultEngine> = RefCell::new(
        DefaultEngine::new(
            Box::new(UnixSeeder::new(UNSAFE_SECRET))
        )
    );
}

// Somewhere later in your program ...

fn main(){
    let raw_cleartext = 8u32;
    let cleartext: Cleartext32 = DEFAULT_ENGINE.with(|eng|{
        eng.create_cleartext_from(&raw_cleartext).unwrap()
    });

    // ...
}
```
