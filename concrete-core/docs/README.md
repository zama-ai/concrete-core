---
description: >-
  ⭐️ Star the repo on Github | 🗣 Community support forum | 📁 Contribute to the
  project
---

# Concrete Core

 Welcome to the `concrete-core` documentation!

 This library contains a set of low-level primitives which can be used to implement *Fully
 Homomorphically Encrypted* (FHE) programs. In a nutshell, fully homomorphic encryption makes it
 possible to perform arbitrary computations over encrypted data. With FHE, you can perform
 computations without putting your trust in third-party computation providers.

 # Audience

 This library is geared towards people who already know their way around FHE. It gives the user
 freedom of choice over a breadth of parameters, which can lead to less than 128 bits of security
 if chosen incorrectly.

 Fortunately, we propose multiple libraries that are built on top of `concrete-core` and which
 propose a safer API. To see which one best suits your needs, see the
 [concrete homepage](https://zama.ai/concrete).

 # Architecture

 `concrete-core` is a modular library which makes it possible to use different backends to
 perform FHE operations. Its design revolves around two modules:

 + The [`specification`] module contains a specification (in the form of traits) of the
 `concrete` FHE scheme. It describes the FHE objects and operators, which are exposed by the
 library.
 + The [`backends`] module contains various backends implementing all or a part of this scheme.
 These different backends can be activated by feature flags, each making use of different
 hardware or system libraries to make the operations faster. Check the [Rust documentation](https://docs.rs/concrete-core/1.0.0-gamma/concrete_core) for a full description of supported backends, engines and entities.

 # Activating backends

 The different backends can be activated using the feature flags `backend_*`. The `backend_default`
 contains an engine executing operations on CPUs. It is activated by default.

## Warning

This crate assumes that the user is comfortable with the theory behind FHE. If you prefer to use a
simpler API, that will perform sanity checks on your behalf, the higher-level `concrete`
crate should have your back.

## Example

Here is a small example of how one could use `concrete-core` to perform a simple operation
homomorphically:

```rust
// This examples shows how to multiply a secret value by a public one homomorphically.
// First we import the proper symbols:

use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let lwe_dimension = LweDimension(750);
    let noise = Variance(2_f64.powf(-104.));

    // Here a hard-set encoding is applied on the input (shift by 59 bits) which corresponds here
    // to a precision of 4 bits with an additional bit of padding (won't be used but required for
    // PBS)
    let raw_input = 3_u64 << 59;

    // We will multiply by 4
    let raw_input_cleatext = 4_u64;

    // Unix seeder must be given a secret input.
    // Here we just give it 0, which is totally unsafe.
    const UNSAFE_SECRET: u128 = 0;
    let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;

    // We create a cleartext from the raw cleartext
    let cleartext: Cleartext64 = engine.create_cleartext(&raw_input_cleatext)?;
    let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;

    // We crate the input plaintext from the raw input
    let input_plaintext = engine.create_plaintext(&raw_input)?;
    let input_ciphertext = engine.encrypt_lwe_ciphertext(&key, &input_plaintext, noise)?;

    // The content of the output ciphertext will be discarded, use a placeholder plaintext of 0
    let placeholder_output_plaintext = engine.create_plaintext(&0u64)?;
    let mut ouptut_ciphertext =
        engine.encrypt_lwe_ciphertext(&key, &placeholder_output_plaintext, noise)?;

    // Perform the multiplication, overwriting (discarding) the output ciphertext content
    engine.discard_mul_lwe_ciphertext_cleartext(
        &mut ouptut_ciphertext,
        &input_ciphertext,
        &cleartext
    )?;

    // Get the decrypted result as a plaintext and then a raw value
    let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &ouptut_ciphertext)?;
    let raw_decrypted_plaintext = engine.retrieve_plaintext(&decrypted_plaintext)?;

    // Round the output for our 4 bits of precision
    let output = raw_decrypted_plaintext >> 58;
    let carry = output % 2;
    let output = ((output >> 1) + carry) % (1 << 5);

    // Check the high bits have the result we expect
    assert_eq!(output, 12);

    engine.destroy(cleartext)?;
    engine.destroy(key)?;
    engine.destroy(input_plaintext)?;
    engine.destroy(placeholder_output_plaintext)?;
    engine.destroy(decrypted_plaintext)?;
    engine.destroy(input_ciphertext)?;
    engine.destroy(ouptut_ciphertext)?;

    Ok(())
}
```

## Links

* [TFHE](https://eprint.iacr.org/2018/421.pdf)
* [concrete-core-1.0.0-alpha release](https://community.zama.ai/t/concrete-core-v1-0-0-alpha/120)
* [concrete-core-1.0.0-beta release](https://www.zama.ai/post/announcing-concrete-core-v1-0-beta)

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions, 
please contact us at `hello@zama.ai`.
