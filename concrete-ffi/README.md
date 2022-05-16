# Concrete Foreign Function Interface

This crate exposes an experimental C FFI to the `concrete-core` primitives. Using this FFI, any language can benefit from the FHE scheme proposed in `concrete`.

This FFI is currently experimental and therefore unstable in terms of naming and exposed structures/entry points.

## An example

DISCLAIMER: the parameters in the example below are insecure and for example purposes only.

Here is a small-ish example of how to call `concrete-core` from C through `concrete-ffi` to compute the homomorphic addition of two ciphertexts. This needs to be linked against `libconcrete_ffi`.

```c
#include "concrete-ffi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

const int MESSAGE_BITS = 4;
const int SHIFT = 64 - (MESSAGE_BITS + 1);

int main(void) {
    SeederBuilder* builder = NULL;

    bool unix_seeder_available = false;
    int unix_seeder_available_ok = unix_seeder_is_available(&unix_seeder_available);
    assert(unix_seeder_available_ok == 0);

    if (unix_seeder_available) {
        // DANGER DANGER DANGER DANGER DANGER DANGER
        // HIGHLY UNSAFE ONLY FOR TESTING PURPOSES
        uint64_t secret_high_64 = 0;
        uint64_t secret_low_64 = 0;
        int get_builder_ok = get_unix_seeder_builder(secret_high_64, secret_low_64, &builder);
        assert(get_builder_ok == 0);
    }
    else {
        printf("UNIX seeder unavailable on this system.\n");
        return EXIT_FAILURE;
    }

    DefaultEngine *engine = NULL;

    int default_engine_ok = new_default_engine(builder, &engine);
    assert(default_engine_ok == 0);
    double variance = 0.000000001;

    // We generate the secret key
    size_t lwe_dimension = 10;
    LweSecretKey64 *sk = NULL;
    int sk_ok = default_engine_create_lwe_secret_key_u64(engine, lwe_dimension, &sk);
    assert(sk_ok == 0);

    // We allocate the ciphertext buffer
    uint64_t *input_ct_1_buffer =
        aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
    uint64_t *input_ct_2_buffer =
        aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
    uint64_t *output_ct_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
    uint64_t plaintext_1 = {((uint64_t)1) << SHIFT};
    uint64_t plaintext_2 = {((uint64_t)2) << SHIFT};

    // We encrypt the plaintext
    int enc_ct_1_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, sk, input_ct_1_buffer, plaintext_1, variance);
    assert(enc_ct_1_ok == 0);
    int enc_ct_2_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, sk, input_ct_2_buffer, plaintext_2, variance);
    assert(enc_ct_2_ok == 0);

    // Perform the addition
    int add_ok = default_engine_discard_add_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, output_ct_buffer, input_ct_1_buffer, input_ct_2_buffer, lwe_dimension);
    assert(add_ok == 0);

    // We decrypt the plaintext
    uint64_t output = -1;
    int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, sk, output_ct_buffer, &output);
    assert(decrypt_ok == 0);

    // We check that the output are the same
    double expected = ((double)plaintext_2 + (double)plaintext_1) / pow(2, SHIFT);
    double obtained = (double)output / pow(2, SHIFT);
    printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
    double abs_diff = abs(obtained - expected);
    double rel_error = abs_diff / fmax(expected, obtained);
    assert(rel_error < 0.002);

    // We deallocate the objects
    default_engine_destroy_lwe_secret_key_u64(engine, sk);
    destroy_default_engine(engine);
    destroy_seeder_builder(builder);
    free(input_ct_1_buffer);
    free(input_ct_2_buffer);
    free(output_ct_buffer);

    return EXIT_SUCCESS;
}
```

## Links

- [TFHE](https://eprint.iacr.org/2018/421.pdf)
- [concrete-core-1.0.0-alpha release](https://community.zama.ai/t/concrete-core-v1-0-0-alpha/120)

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
