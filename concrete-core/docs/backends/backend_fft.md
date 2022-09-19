# FFT backend

The FFT backend implements engines that require the transformation of polynomials from/to the Fourier domain.
The Fourier conversions rely on a custom Rust FFT implementation, via a dependency to `concrete-fft`.

## Features
A serialization feature can be activated on top of the FFT backend, just like for the default backend via the `backend_fft_serialization` feature.
You can also leverage improved performance with the feature `backend_fft_nightly_avx512`. You then have to execute your code using `cargo +nightly`.

## Supported parameter sets

This backend supports any value for the polynomial size that is a power of 2. Increasing the polynomial size makes it possible to operate on messages with more precision, but you cannot expect arbitrary precision via the FFT due to the underlying floating point arithmetics that introduces noise. Otherwise, any value of base log, number of levels for the decomposition, LWE dimension and GLWE dimension can take arbitrary values.

## Tutorial

In this tutorial, we'll see how to use the FFT backend to run a bootstrap and a keyswitch operation. In the `Cargo.toml` file, you just need to add `backend_fft` to the features activated on `concrete-core`:
```shell
concrete-core = {version = "=1.0.0", features=["backend_default", "backend_fft", "backend_default_parallel"]}
```
Just like in the default backend tutorial, we first define some cryptographic parameters (that are unsecure and do not guarantee that the output is unaffected by the noise):
```rust
fn main() {
    // We generate the various keys.
    // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    
    // We generate the secret keys ...
    let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    let glwe_sk: GlweSecretKey64 =
        default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    
    // We generate the bootstrap keys in parallel and transfer to the fourier domain ...
    let bsk: LweBootstrapKey64 = parallel_engine
        .generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, pbs_dec_bl, pbs_dec_lc, glwe_noise)?;
    let bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    
    // We generate the keyswitch key to move the ciphertext back to the initial key ...
    let lwe_interm_sk: LweSecretKey64 =
        default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk)?;
    let ksk: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
        &lwe_interm_sk,
        &lwe_sk,
        ks_dec_lc,
        ks_dec_bl,
        lwe_noise,
    )?;
}
```

Now, we can create the engines we'll need, as well as the secret keys and the bootstrap key, just like in the previous tutorial:
```rust
fn main(){
    // We instantiate the engines needed for the computations.
    // Here we need to create a secret to give to the unix seeder, but we skip the actual secret creation
    const UNSAFE_SECRET: u128 = 0;
    let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    let mut parallel_engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET))).unwrap();
    let mut fft_engine = FftEngine::new(())?;
}
```

Then, let's define an input to be encrypted, and encrypt it to an lwe ciphertext:
```rust
fn main(){
    // We encode and encrypt the message.
    let input_raw = 3_u64 << encode_shift;
    let input_plaintext = default_engine.create_plaintext_from(&input_raw)?;
    let input_lwe = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &input_plaintext, lwe_noise)?;
}
```
We will thus be encrypting the value 3 into a ciphertext represented with u64 integers. The message
is encoded into the most significant bits of the u64 integer with a shift of 59 bits, to avoid 
having the message erased by the noise.

We also generate the lookup table applied during the bootstrap. Here, the function encoded by the 
lookup table is a simple constant function that returns the value 8:
```rust
fn main(){
    // We encode and (trivially) encrypt the lut.
    let lut_raw = vec![8_u64 << encode_shift; poly_size.0];
    let lut_plaintext_vector = default_engine.create_plaintext_vector_from(&lut_raw)?;
    let lut_glwe = default_engine
        .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &lut_plaintext_vector)?;
}
```

We're now ready to execute the bootstrap over the input. We need to first allocate a container for 
the output. For that we can use the zero encryption :
```rust
fn main(){
    // We perform the bootstrap.
    let mut interm_lwe =
        default_engine.zero_encrypt_lwe_ciphertext(&lwe_interm_sk, lwe_noise)?;
    fft_engine.discard_bootstrap_lwe_ciphertext(&mut interm_lwe, &input_lwe, &lut_glwe, &bsk)?;
}
```

The bootstrap returns a ciphertext under a different secret key then the one used initially. We 
have to keyswitch to come back to the original secret key:
```rust
fn main(){
    // We perform the keyswitch to move back to the initial secret key.
    let mut output_lwe = default_engine.zero_encrypt_lwe_ciphertext(&lwe_sk, lwe_noise)?;
    default_engine.discard_keyswitch_lwe_ciphertext(&mut output_lwe, &interm_lwe, &ksk)?;
}
```

We can now decrypt and decode the output value with the initial key:
```rust
fn main () {
    // We decrypt the output.
    let output_plaintext = default_engine.decrypt_lwe_ciphertext(&lwe_sk, &output_lwe)?;
    let output_raw = default_engine.retrieve_plaintext(&output_plaintext)?;

    // We decode and round.
    let decoded = output_raw >> (encode_shift - 1);
    let carry = decoded % 2;
    let decoded = ((decoded >> 1) + carry) % (1 << (64 - encode_shift));
}
```


And that's it! You'll notice that the bootstrap is a slow operation: it is actually the bottleneck for performance in TFHE.
The next tutorial about the [Cuda backend](backend_cuda.md) will show you how to speed up this operation using GPU acceleration.

## Large precision programmable bootstrap tutorial

In this tutorial we will see how to use the FFT backend to run the so-called without padding bit PBS (wop PBS), which makes it possible to apply a programmable bootstrap on ciphertexts encrypting messages with up to 16 bits, without relying on large polynomial sizes.

In the `Cargo.toml` file, you need to add `backend_fft` to the features activated on `concrete-core`:

```toml
concrete-core = {version = "=1.0.0", features=["backend_default", "backend_fft", "backend_default_parallel"]}
```

The main difference between the PBS and wop PBS is that the latter operates over individual ciphertexts containing encrypted bits to evaluate a look-up table, while the former works on a single ciphertext encrypting a value over several bits.

The basic idea is the following:

An LWE ciphertext (or a collection of LWE ciphertexts) containing several encrypted bits of information, is (or each item of the collection is) first processed to extract all encrypted information in several so-called "boolean" LWE ciphertexts, encrypting a single bit of information each. This step is called the "bit extraction".

These ciphertexts are then turned into GGSW ciphertexts thanks to an operation called the "circuit bootstrapping". Having GGSW ciphertexts is interesting as they can be used to perform Cmux operations (basically an if/else operation), then serving as control bits during the evaluation of the look-up table.

The final step consists in evaluating one or several look-up tables using the GGSW ciphertexts in an operation called "vertical packing". Each look-up table evaluation will yield an LWE ciphertext, this means that you can output the result over several ciphertexts if you need to store a lot of information (for example splitting a 16 bits value over two 8 bits LWE ciphertexts).

One note about the look-up table format:

Let's take an example where we have 11 encrypted bits after the bit extraction and we want to use a polynomial size of 512 during the wop PBS evaluation. The look-up tables will contain polynomials of size 512 but 512 is smaller than the 2048 values representable by the 11 bits we have as inputs. To manage that we need to create so-called "big look-up tables". A big look-up table needs to contain as much information as the number of input bits we have, so here a big look-up table needs to have a size of 2048 in total, so we would fit four small look-up tables of size 512 in the big look-up table. The ordering here is important, the index of a small look-up table indicates in which condition it will be used for computation. Basically the small look-up table at index 0 will be used if the two most significant bit is are 0, as 0 in binary is 0b00, the small look-up table at index 1 will be used if the two most significant bits are 0b01 as 1 == 0b01, etc. The number of most significant bits used for this first look-up table selection is the log2 of the number of small look-up tables in a big look-up table. Then the remaining bits are used in a blind rotation to select the value from the previously selected look-up table with the most significant bits we just mentioned.

In practice, for small amounts of bits you may want to use "trivial" look-up tables which already have the right number of values inside them, given the number of bits that were extracted. But in cases where you have more than 14 bits you will need this trick as the wop PBS uses operations that don't support look-up table sizes greater than 16 384 (== 2 ^ 14).

```rust
use concrete_core::commons::math::decomposition::SignedDecomposer;
use concrete_core::prelude::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(481);

    let var_small = Variance::from_variance(2f64.powf(-80.0));
    let var_big = Variance::from_variance(2f64.powf(-70.0));

    // Create the required engines
    const UNSAFE_SECRET: u128 = 0;
    let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    let mut default_parallel_engine =
        DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    let mut fft_engine = FftEngine::new(())?;

    // Generate keys for encryption and evaluation
    let glwe_sk: GlweSecretKey64 =
        default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    let lwe_small_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    let lwe_big_sk: LweSecretKey64 =
        default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;

    let bsk_level_count = DecompositionLevelCount(9);
    let bsk_base_log = DecompositionBaseLog(4);

    let std_bsk: LweBootstrapKey64 = default_parallel_engine.generate_new_lwe_bootstrap_key(
        &lwe_small_sk,
        &glwe_sk,
        bsk_base_log,
        bsk_level_count,
        var_small,
    )?;

    let fourier_bsk: FftFourierLweBootstrapKey64 =
        fft_engine.convert_lwe_bootstrap_key(&std_bsk)?;

    let ksk_level_count = DecompositionLevelCount(9);
    let ksk_base_log = DecompositionBaseLog(1);

    let ksk_big_to_small: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
        &lwe_big_sk,
        &lwe_small_sk,
        ksk_level_count,
        ksk_base_log,
        var_big,
    )?;

    let pfpksk_level_count = DecompositionLevelCount(9);
    let pfpksk_base_log = DecompositionBaseLog(4);

    let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 = default_engine
        .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
            &lwe_big_sk,
            &glwe_sk,
            pfpksk_base_log,
            pfpksk_level_count,
            var_small,
        )?;

    // We will have a message with 10 bits of information and we will extract all of them
    let message_bits = 10;
    let bits_to_extract = ExtractedBitsCount(message_bits);

    // The value we encrypt is 42, we will extract the bits of this value and apply the
    // circuit bootstrapping followed by the vertical packing on the extracted bits.
    let cleartext = 42;
    let delta_log_msg = DeltaLog(64 - message_bits);

    // We encode the message on the most significant bits
    let encoded_message = default_engine.create_plaintext_from(&(cleartext << delta_log_msg.0))?;
    let lwe_in = default_engine.encrypt_lwe_ciphertext(&lwe_big_sk, &encoded_message, var_big)?;

    // Bit extraction output, use the zero_encrypt engine to allocate a ciphertext vector
    let mut bit_extraction_output = default_engine.zero_encrypt_lwe_ciphertext_vector(
        &lwe_small_sk,
        var_small,
        LweCiphertextCount(bits_to_extract.0),
    )?;

    // Perform the bit extraction.
    fft_engine.discard_extract_bits_lwe_ciphertext(
        &mut bit_extraction_output,
        &lwe_in,
        &fourier_bsk,
        &ksk_big_to_small,
        bits_to_extract,
        delta_log_msg,
    )?;

    // Though the delta log here is the same as the message delta log, in the general case they
    // are different, so we create two DeltaLog parameters
    let delta_log_lut = DeltaLog(64 - message_bits);

    // Create a look-up table we want to apply during vertical packing, here we will perform the
    // addition of the constant 1 and we will apply the right encoding and modulus operation.
    // Adapt the LUT generation to your usage.
    // Here we apply a single look-up table as we output a single ciphertext.
    let number_of_luts_and_output_vp_ciphertexts = 1;
    let lut_size = 1 << bits_to_extract.0;
    let mut lut: Vec<u64> = Vec::with_capacity(lut_size);

    for i in 0..lut_size {
        lut.push(((i as u64 + 1) % (1 << message_bits)) << delta_log_lut.0);
    }

    let lut_as_plaintext_vector = default_engine.create_plaintext_vector_from(lut.as_slice())?;

    // We run on views, so we need a container for the output
    let mut output_cbs_vp_ct_container = vec![
        0u64;
        lwe_big_sk.lwe_dimension().to_lwe_size().0
            * number_of_luts_and_output_vp_ciphertexts
    ];

    let mut output_cbs_vp_ct_mut_view: LweCiphertextVectorMutView64 = default_engine
        .create_lwe_ciphertext_vector_from(
            output_cbs_vp_ct_container.as_mut_slice(),
            lwe_big_sk.lwe_dimension().to_lwe_size(),
        )?;

    // And we need to get a view on the bits extracted earlier that serve as inputs to the
    // circuit bootstrap + vertical packing
    let extracted_bits_lwe_size = bit_extraction_output.lwe_dimension().to_lwe_size();
    let extracted_bits_container =
        default_engine.consume_retrieve_lwe_ciphertext_vector(bit_extraction_output)?;
    let cbs_vp_input_vector_view: LweCiphertextVectorView64 = default_engine
        .create_lwe_ciphertext_vector_from(
            extracted_bits_container.as_slice(),
            extracted_bits_lwe_size,
        )?;

    let cbs_level_count = DecompositionLevelCount(4);
    let cbs_base_log = DecompositionBaseLog(6);

    fft_engine.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
        &mut output_cbs_vp_ct_mut_view,
        &cbs_vp_input_vector_view,
        &fourier_bsk,
        &lut_as_plaintext_vector,
        cbs_level_count,
        cbs_base_log,
        &cbs_pfpksk,
    )?;

    let lwe_ciphertext_vector_container_as_slice =
        &*default_engine.consume_retrieve_lwe_ciphertext_vector(output_cbs_vp_ct_mut_view)?;

    let output_cbs_vp_ct_view: LweCiphertextVectorView64 = default_engine
        .create_lwe_ciphertext_vector_from(
            lwe_ciphertext_vector_container_as_slice,
            lwe_big_sk.lwe_dimension().to_lwe_size(),
        )?;

    let decrypted_output =
        default_engine.decrypt_lwe_ciphertext_vector(&lwe_big_sk, &output_cbs_vp_ct_view)?;
    let decrypted_plaintext = default_engine.retrieve_plaintext_vector(&decrypted_output)?;

    // We want to work on 10 bits values, so pick a decomposer for 1 single level of 10 bits
    let decomposer =
        SignedDecomposer::new(DecompositionBaseLog(10), DecompositionLevelCount(1));

    let rounded_output = decomposer.closest_representable(decrypted_plaintext[0]);

    let decoded_output = rounded_output >> delta_log_lut.0;

    // 42 + 1 == 43 in our 10 bits output ciphertext
    assert_eq!(decoded_output, 43);

    Ok(())
}
```
