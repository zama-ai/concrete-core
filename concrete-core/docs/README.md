# What is Concrete-core?

⭐️ [Star the repo on Github](https://github.com/zama-ai/Concrete-core) | 🗣 [Community support forum](https://community.zama.ai/c/concrete-lib) | 📁 [Contribute to the project](https://github.com/zama-ai/Concrete-core#contributing)

<figure><img src="_static/concrete_core_doc.png" alt=""><figcaption></figcaption></figure>

This library contains a set of low-level primitives which can be used to implement _Fully Homomorphically Encrypted_ (FHE) programs. In a nutshell, FHE makes it possible to perform arbitrary computations over encrypted data. With FHE, you can perform computations without putting your trust in third-party computation providers.

At first, `Concrete-core` was only a CPU implementation of those cryptographic primitives. But soon it became vital to integrate hardware accelerations of those, for performance reasons. At the same time, projects built from `Concrete-core` turned out to be not only Rust projects, but also Javascript or C++ ones. In the view of this, `Concrete-core` was turned into a platform geared towards the integration of hardware acceleration of cryptographic primitives, that also has the ability to generate APIs to other languages very easily.

## Audience

This library is geared towards people who already know their way around FHE. It gives the user freedom of choice over a breadth of parameters, which can lead to less than 128 bits of security if chosen incorrectly.

Fortunately, multiple libraries are built on top of `Concrete-core` that propose a safer API. To see which one best suits your needs, see the [concrete homepage](https://zama.ai/concrete).

## Cross-language support

The main package in the repository is `concrete-core`, the Rust implementation. Then, a C API is exposed in `concrete-core-ffi`, and a Javascript API is exposed in `concrete-core-wasm`.

## Architecture

`Concrete-core` is a modular library which makes it possible to use different backends to perform FHE operations. The term backends here refers to an implementation of some, or all, cryptographic features supported in `Concrete-core`, on a given hardware. The same operation can be implemented in any number of backends. If your platform supports it, you can activate as many backends at once as you want.

The library's design revolves around two modules:

* The \[`specification`] module contains a specification (in the form of Rust traits) of the FHE objects and operators that are exposed by the library: it states what are the operations that are supported, and what are the types of their inputs and outputs.
* The \[`backends`] module contains various backends implementing all or a part of this scheme. These different backends can be activated by feature flags, each making use of different hardware or system libraries to make the operations faster.

## Rust documentation

The [Rust documentation](https://docs.rs/concrete-core/1.0.0/concrete\_core) provides the full description of supported backends, data types and operations. For each implementation of an operation in a backend, an example of use is provided via a code snippet.

## Activating backends

The different backends can be activated using the feature flags `backend_*`. The `backend_default` contains an engine executing operations on CPUs. It is activated by default.

## Warning

This crate assumes that the user is comfortable with the theory behind FHE. If you prefer to use a simpler API, that will perform sanity checks on your behalf, the higher-level [`Concrete`](https://docs.zama.ai/concrete) crate should have your back.

## Quick start

Head to the [quick start page](getting\_started/quick\_start.md) for an example of how to use `Concrete-core`. It explains the example below step by step:

```rust
// This examples shows how to multiply a secret value by a public one homomorphically.

// First we import the proper symbols
use concrete_core::prelude::Variance;
use concrete_core::prelude::LweDimension;
use concrete_core::prelude::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
 // DISCLAIMER: the parameters used here are only for test purpose, and cannot be considered secure.
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
 let cleartext: Cleartext64 = engine.create_cleartext_from(&raw_input_cleatext)?;
 let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;

 // We crate the input plaintext from the raw input
 let input_plaintext = engine.create_plaintext_from(&raw_input)?;
 let input_ciphertext = engine.encrypt_lwe_ciphertext(&key, &input_plaintext, noise)?;

 // Create a container for the output, whose content will be discarded during the operation
 let mut output_ciphertext =
         engine.trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &input_plaintext)?;

 // Perform the multiplication, overwriting (discarding) the output ciphertext content
 engine.discard_mul_lwe_ciphertext_cleartext(
  &mut output_ciphertext,
  &input_ciphertext,
  &cleartext
 )?;

 // Get the decrypted result as a plaintext and then a raw value
 let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &output_ciphertext)?;
 let raw_decrypted_plaintext = engine.retrieve_plaintext(&decrypted_plaintext)?;

 // Round the output for our 4 bits of precision
 let output = raw_decrypted_plaintext >> 58;
 let carry = output % 2;
 let output = ((output >> 1) + carry) % (1 << 5);

 // Check the high bits have the result we expect
 assert_eq!(output, 12);

 Ok(())
}
```

## Links

* [TFHE](https://eprint.iacr.org/2021/091.pdf)

## License

This software is distributed under the BSD-3-Clause-Clear license.&#x20;

If you have any questions, please contact us at `hello@zama.ai`.

## Additional resources

* [Dedicated community support forum](https://community.zama.ai/c/concrete-ml/8)
* [Zama's blog](https://www.zama.ai/blog)
* [FHE.org community](https://fhe.org)

## Looking for support? Ask our team!

* Support forum: [https://community.zama.ai](https://community.zama.ai) (we answer in less than 24 hours).
* Live discussion on the FHE.org discord server: [https://discord.fhe.org](https://discord.fhe.org) (inside the #**concrete** channel).
* A question about Zama? You can write us on [Twitter](https://twitter.com/zama\_fhe) or send us an email at: **hello@zama.ai**
