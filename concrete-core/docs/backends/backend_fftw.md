# FFTW backend

The FFTW backend implements engines that require the transformation of polynomials from/to the Fourier domain.
The Fourier conversions rely on the FFTW library, via a dependency to `concrete-fftw`, where the transformations are turned in their negacyclic counterparts.
This backend is thus longer to compile than the default backend, and the resulting binary is larger.
A serialization feature can be activated on top of the FFTW backend, just like for the default backend.

## Tutorial

In this tutorial, we'll see how to use the FFTW backend to run a bootstrap operation. In the `Cargo.toml` file,
you just need to add `backend_fftw` to the features activated on `concrete-core`:
```shell
concrete-core = {version = "=1.0.0-gamma", features=["backend_default", "backend_fftw", "backend_default_parallel"]}
```
Just like in the default backend tutorial, we first define some cryptographic parameters (that are unsecure and do not guarantee that the output is unaffected by the noise):
```rust
    // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
        LweDimension(600),
        LweDimension(2048),
        GlweDimension(1),
        PolynomialSize(2048),
    );
    let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    let noise = Variance(2_f64.powf(-60.));
```
Then, let's define an input to be encrypted, and a lookup table that's going to be used in the bootstrap:
```rust

    // We define an input. Here a hard-set encoding is applied (shift by 61 bits)
    let input = 3_u64 << 61;
    // A constant function is applied during the bootstrap
    let lut = vec![2_u64 << 61; poly_size.0];
```
We will thus be encrypting the value 3 into a ciphertext represented with u64 integers. The lookup table applied during the bootstrap
will simply be a constant, 2. Both the message and the lookup table values are encoded into the most significant bits of the
u64 integer, with a shift of 61 bits, to avoid having the message erased by the noise.

Now, we can create the engines we'll need, as well as the secret keys and the bootstrap key, just like in the previous tutorial:
```rust
    // Create the necessary engines
    // Here we need to create a secret to give to the unix seeder, but we skip the actual secret creation
    const UNSAFE_SECRET: u128 = 0;
    let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET))).unwrap();
    let mut fftw_engine = FftwEngine::new(()).unwrap();
    let mut parallel_engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET))).unwrap();

    // Create the secret keys
    let lwe_sk: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dim).unwrap();
    let glwe_sk: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dim, poly_size).unwrap();

    // The bootstrap key is created with multithreading, relying on rayon
    let bsk: LweBootstrapKey64 =
        parallel_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise).unwrap();
```
We're now going to encrypt the input message and the lookup table:
```rust
    // Now we have all the keys, prepare the ciphertexts
    let plaintext = engine.create_plaintext(&input).unwrap();
    let input = engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise).unwrap();
    // Then the encryption of the LUT for the bootstrap
    let lut_plaintext_vector = engine.create_plaintext_vector(&lut).unwrap();
    let acc =
    engine.trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(),
    &lut_plaintext_vector).unwrap();
```
We also need to prepare a container for the output LWE of the bootstrap. For this we can simply use a trivial encryption:
```rust
    // Finally an output whose content will be overwritten by the bootstrap
    let mut output_ciphertext = engine.trivially_encrypt_lwe_ciphertext(lwe_dim_output.to_lwe_size(),
    &plaintext).unwrap();
```
The bootstrap engine takes as input the bootstrap key in the Fourier domain. We thus need to convert our
bootstrap key using the FFTW backend:

```rust
    // Convert the bootstrap key to the Fourier domain using FFTW
    let fourier_bsk: FftwFourierLweBootstrapKey64 =
    fftw_engine.convert_lwe_bootstrap_key(&bsk).unwrap();
```
We're now ready to execute the bootstrap over the input, relying on FFTW:
```rust
    fftw_engine.discard_bootstrap_lwe_ciphertext(&mut output_ciphertext, &input, &acc,
                                                 &fourier_bsk).unwrap();
```
In order to decrypt the output, we have to create the output LWE secret key by transforming the 
GLWE secret key that was used to create the bootstrap key.
Then we can decrypt the result of the bootstrap:
```rust
    let lwe_sk_output: LweSecretKey64 = engine.transform_glwe_secret_key_to_lwe_secret_key
    (glwe_sk).unwrap();
    let output = engine.decrypt_lwe_ciphertext(&lwe_sk_output, &output_ciphertext).unwrap();
```
Finally, we can destroy all data:
```rust
    // Destroying the secret keys is important since their content is reset to 0 before dropping 
    // memory, to defend against potential attacks (this actually doesn't work currently due to 
    // the rust compiler, we should fix it next quarter)
    engine.destroy(lwe_sk).unwrap();
    engine.destroy(bsk).unwrap();
    engine.destroy(lwe_sk_output).unwrap();

    fftw_engine.destroy(fourier_bsk).unwrap();
    engine.destroy(plaintext).unwrap();
    engine.destroy(lut_plaintext_vector).unwrap();
    engine.destroy(acc).unwrap();
    engine.destroy(input).unwrap();
    engine.destroy(output_ciphertext).unwrap();
    engine.destroy(output).unwrap();
}
```

And that's it! You'll notice that the bootstrap is a slow operation: it is actually the bottleneck for performance in TFHE.
The next tutorial about the [Cuda backend](backend_cuda.md) will show you how to accelerate this operation using GPU acceleration.