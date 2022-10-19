# Quick Start

Let's go over the example shown in the introduction, step by step. This example shows how to multiply a secret value by a public one, homomorphically.

### Imports

All data types and operations in `Concrete-core` are made available via a prelude to simplify imports.

```rust
use concrete_core::prelude::*;
use std::error::Error;
```

### Error management

```rust
fn main() -> Result<(), Box<dyn Error>> {
```

This is a classical Rust signature: the main function returns an `Error` via the `Result` type. Error cases are reviewed in `Concrete-core` and dedicated error messages are returned when such cases are discovered during execution. In this example, all operations that propagate errors via the `?` symbol are concerned.

Let's look at the `discard_mul_lwe_ciphertext_cleartext` operation: the dimension of the input is checked to be equal to that of the provided output at execution time. The error message returned in case of mismatch is:

```rust
"The input and output ciphertext LWE dimension must be the same."
```

The list of supported errors for this operation is available [here](https://docs.rs/concrete-core/1.0.0/concrete\_core/specification/engines/enum.LweCiphertextCleartextDiscardingMultiplicationError.html#variants), in the `Variants` section.

The full list of supported error types is available [here](https://docs.rs/concrete-core/1.0.0/concrete\_core/specification/engines/#enums), in the `Enums` section.

The errors managed by `Concrete-core` are checks regarding the compatibility of **cryptographic parameters**. <mark style="background-color:yellow;">There are no checks that when decrypting a ciphertext, the same secret key than the one used for encryption is used.</mark> This is left to the user to handle.

### Parameters choice

The choice of cryptographic parameters is also the responsibility of the user as of now. In this example, there are two parameters to choose from: the LWE dimension of the ciphertext and the variance of the noise used during encryption.

```rust
    let lwe_dimension = LweDimension(750);
    let noise = Variance(2_f64.powf(-104.));
```

The choice of parameters is not easy, and can lead to less than 128 bits of security. If you are not comfortable choosing the parameters yourself, you can check the [`Concrete`](https://docs.zama.ai/concrete) library, where sets of parameters are proposed for various usages of `Concrete-core`.

It is of course up to you to choose what message to encrypt, how it is encoded, and what public value to use for the multiplication. In this example, the value `3` is encrypted into a ciphertext with a 64-bits integer representation. An encoding is applied onto the input message, so that it is located in the most significant bits of the ciphertext. Otherwise it would end up being covered by the noise, and decryption wouldn't yield the expected result. Here, the message is shifted by 59 bits, which corresponds to 4 bits of message plus an additional bit of padding (the padding bit won't be used in the example, but would be required for a programmable bootstrap). The public value of `4` is then multiplied to the ciphertext: at the end of this example, after decryption, it is expected to recover the value `12`.

```rust
    // We choose a message: 3, encoded with a 59 bits left-shift
    let raw_input = 3_u64 << 59;

    // We will multiply by 4
    let raw_input_cleartext = 4_u64;
```

### Seeder choice

Now let's head over to the encryption stage. Encryption itself relies on secure random number generation, for which a seeder is required. There are currently two choices of seeder in `Concrete-core`: one relying on the `rdseed` instruction available on x86\_64 Intel processors and another that relies on the `/dev/random` file available on Unix platforms. The `rdseed`-based seeder is absolutely recommended on platforms that support it, since it can be considered secure, whereas the `/dev/random` file cannot be considered to be a secure source of entropy on some platforms. This is why currently, for the Unix based seeder, the user is also required to input a secret (a passphrase of your choice) that should **not** be deducible from the state of the machine.

In this example, we pass an unsecure secret to the Unix seeder, which is **not what you should do in a real application**. Instead, you'll have to come up with a system to collect a user passphrase and pass it to `Concrete-core` if you wish to support platforms other than `x86_64`.

```rust
    const UNSAFE_SECRET: u128 = 0;
    let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
```

Here you see that an `engine` variable is created by calling the `new` method of the `DefaultEngine`. This `new` method takes a seeder as input: in this case, the `UnixSeeder` is passed, which takes a secret as argument, as stated earlier.

The alternative is:

```rust
let mut engine = DefaultEngine::new(Box::new(RdseedSeeder))?;
```

In order to use the `rdseed`-based seeder, you have to activate the feature flag `seeder_x86_64_rdseed` in your `Cargo.toml`.

The `engine` vocabulary is specific to `Concrete-core`. To make it short, the `DefaultEngine` is a type that can implement any number of `engine` traits that are supported in the library. Those traits correspond to cryptographic operations. More details about the architecture and vocabulary of `Concrete-core`'s API can be found [here](../general\_concepts/api\_structure.md).

In what follows, the `engine` that was just created is going to be used to execute a number of cryptographic operations. The full list of operations implemented by the `DefaultEngine` is available [here](https://docs.rs/concrete-core/1.0.0/concrete\_core/backends/default/engines/struct.DefaultEngine.html), with code examples for each of them.

### Input generation

Now that the `engine` has been created, let's head to the actual encryption stage. First of all, the public value used for the multiplication needs to be wrapped in a type. In `Concrete-core`, that is called `Cleartext`.

```rust
    let cleartext: Cleartext64 = engine.create_cleartext_from(&raw_input_cleartext)?;
```

Cleartexts are values of arbitrary type (unsigned integer, signed integer, float, structure, etc.) that are not meant to be encrypted but are used during the homomorphic computation. This wrapping was introduced in order to be able to bind the type of cleartext to the integer representation used for the ciphertext. In this case, the cleartext has to be represented with an unsigned integer with the same number of bits as what is used in the ciphertext, via the `Cleartext64` type.

The full list of types implemented in the default backend is available [here](https://docs.rs/concrete-core/1.0.0/concrete\_core/backends/default/entities/index.html).

The encoded message itself is wrapped into a `Plaintext64` type. Plaintexts are unsigned integers that correspond **only** to an encoded message meant to be encrypted.

```rust
    let input_plaintext: Plaintext64 = engine.create_plaintext_from(&raw_input)?;
```

In order to encrypt, a secret key is also required. It can be created as follows:

```rust
    let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
```

In this way, the secret key has as many secret bits as the LWE dimension that was chosen for encryption. The actual encryption can now be performed:

```rust
    let input_ciphertext: LweCiphertext64 = engine.encrypt_lwe_ciphertext(&key, &input_plaintext, noise)?;
```

An input ciphertext of type `LweCiphertext64` is thus generated that encrypts the encoded message chosen earlier, using the secret key `key` and the noise chosen previously.

### Operation execution

We're about ready to execute the operation chosen as example here: the multiplication between a cleartext and a ciphertext. In `Concrete-core` there are currently three types of operations:

* **"Pure" operations** that allocate a container for their outputs: for example the encryption of the LWE ciphertext is returning a newly allocated ciphertext directly.
* **"Discarding" operations** that use a container given as input to place the result of the computation. The content of this pre-allocated object is not used during the computation itself, only to store the result, hence the "discarding" key-word.
* **"Fusing" operations** that also take a container as input to place the result of the computation, but use the content of the container instead of just discarding it.

The operation chosen here is `discard_mul_lwe_ciphertext_cleartext` of the "discarding" type. It is thus necessary to create a container used to store the output of the computation. For this, it is possible to trivially encrypt any value for example, the input plaintext created above. This trivial encryption allocates and initializes a container for the output LWE ciphertext:

```rust
   let mut output_ciphertext: LweCiphertext64 =
     engine.trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &input_plaintext)?;
```

We can finally perform the multiplication, overwriting (discarding) the output ciphertext content:

```rust
    engine.discard_mul_lwe_ciphertext_cleartext(
        &mut output_ciphertext,
        &input_ciphertext,
        &cleartext
    )?;
```

The Rust documentation concerning this operation can be found [here](https://docs.rs/concrete-core/1.0.0/concrete\_core/backends/default/engines/struct.DefaultEngine.html#impl-LweCiphertextCleartextDiscardingMultiplicationEngine%3CLweCiphertext64%2C%20Cleartext64%2C%20LweCiphertext64%3E-for-DefaultEngine).

### Decryption

Now that the homomorphic computation has been performed, let's decrypt the result:

```rust
    // Get the decrypted result as a plaintext and then a raw value
    let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &output_ciphertext)?;
    let raw_decrypted_plaintext = engine.retrieve_plaintext(&decrypted_plaintext)?;
```

Here, two operations are performed: first the decryption itself, then the extraction of the decrypted plaintext into a u64 variable. Finally, the rounding step can be performed to complete the decryption:

```rust
    // Round the output for our 4 bits of precision
    let output = raw_decrypted_plaintext >> 58;
    let carry = output % 2;
    let output = ((output >> 1) + carry) % (1 << 5);
```

And the expected result, 12, is recovered!

```rust
    // Check the high bits have the result we expect
    assert_eq!(output, 12);

    Ok(())
}
```

That's it for this **quick start** tutorial. Head over to the [supported operations page](supported\_operations.md) for more details about what you can do with `Concrete-core`. Then, the **general concepts** section provides more information about the various topics covered in this quick start example, while the **backends** section provides more advanced tutorials.
