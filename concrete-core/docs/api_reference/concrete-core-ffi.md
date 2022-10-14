# Using Concrete-core from C

This library exposes a C binding to the low-level `concrete-core` primitives to implement FHE programs.

Please note that the FFI is very much a prototype at this stage, so not all engines and entities from `concrete-core` are available. The available entry points were written to be used by the `concrete-compiler` and should be enough for most use cases.

## First steps using `concrete-core-ffi`

### Setting-up `concrete-core-ffi` for use in a C program.

You can build `concrete-core-ffi` yourself on a Unix x86\_64 machine using the following command:

```shell
RUSTFLAGS="-Ctarget-cpu=native" cargo build --all-features --release -p concrete-core-ffi
```

All features in the FFI crate are opt-in, but for simplicity, we will enable all of them here.

You can then find the `concrete-core-ffi.h` header as well as the static (.a) and dynamic (.so) `libconcrete_core_ffi` binaries in "${REPO\_ROOT}/target/release/"

Whether you build `concrete-core-ffi` yourself or download a pre-built version, you will need to set up your build system so that your C or C++ program links against `concrete-core-ffi`.

Here is a minimal CMakeLists.txt to do just that:

```cmake
project(my-project)

cmake_minimum_required(VERSION 3.16)

set(CONCRETE_CORE_FFI_RELEASE "/path/to/concrete-core-ffi/binaries/and/header")

include_directories(${CONCRETE_CORE_FFI_RELEASE})
add_library(Concrete STATIC IMPORTED)
set_target_properties(Concrete PROPERTIES IMPORTED_LOCATION ${CONCRETE_CORE_FFI_RELEASE}/libconcrete_core_ffi.a)

set(EXECUTABLE_NAME my-executable)
add_executable(${EXECUTABLE_NAME} main.c)
target_include_directories(${EXECUTABLE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC Concrete m pthread dl)
target_compile_options(${EXECUTABLE_NAME} PRIVATE -Werror)
```

### Commented code of an homomorphic addition done with `concrete-core-ffi`.

Here we will detail the steps required to perform the homomorphic addition of 1 and 2.

WARNING: The following example does not have proper memory management in the error case to make it easier to fit the code on this page.

DISCLAIMER: the parameters in the example below are insecure and for example purposes only.

```c
// First we need some headers

// The header for concrete-core-ffi
#include "concrete-core-ffi.h"

// And some standard headers for other functions we will use in this example
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

// Precision related constants, this requires understanding of the underlying cryptography.
// You can find more information about encoding in this blog post:
// https://www.zama.ai/post/tfhe-deep-dive-part-2
const int MESSAGE_BITS = 4;
const int SHIFT = 64 - (MESSAGE_BITS + 1);

// Our program's entry point
int main(void) {
    // DefaultEngine requires a seeder to seed random number generators for key generation and
    // encryption.
    SeederBuilder* builder = NULL;

    bool unix_seeder_available = false;
    int unix_seeder_available_ok = unix_seeder_is_available(&unix_seeder_available);

    // Here we crash if something goes wrong, you will want to have a different behavior in your
    // production code for better error handling
    if (unix_seeder_available_ok != 0) {
        printf("Error checking Unix seeder availability.\n");
        return unix_seeder_available_ok;
    }

    if (unix_seeder_available) {
        // DANGER DANGER DANGER DANGER DANGER DANGER
        // HIGHLY UNSAFE ONLY FOR TESTING PURPOSES
        uint64_t secret_high_64 = 0;
        uint64_t secret_low_64 = 0;
        int get_builder_ok = get_unix_seeder_builder(secret_high_64, secret_low_64, &builder);
        if (get_builder_ok != 0) {
            printf("Error getting the Unix seeder builder.\n");
            return get_builder_ok;
        }
    }
    else {
        printf("UNIX seeder unavailable on this system.\n");
        return EXIT_FAILURE;
    }

    // Pointer for the engine we will instantiate and later use
    DefaultEngine *engine = NULL;

    // Instantiate the DefaultEngine, used as the main entry point to the concrete-core API
    int default_engine_ok = new_default_engine(builder, &engine);
    if (default_engine_ok != 0) {
        printf("Error while creating DefaultEngine.\n");
        return default_engine_ok;
    }

    // We select the size of the mask for LWE ciphertexts. Note that theses parameters are not
    // secure and are given for example purposes only.
    // You can find more information about LWE encryption in this blog post:
    // https://www.zama.ai/post/tfhe-deep-dive-part-1
    size_t lwe_dimension = 10;
    LweSecretKey64 *sk = NULL;
    // We generate the secret key
    int sk_ok = default_engine_generate_new_lwe_secret_key_u64(engine, lwe_dimension, &sk);
    if (sk_ok != 0) {
        printf("Error while creating LWE secret key.\n");
        return sk_ok;
    }

    // For now concrete-core-ffi expects the caller to provide memory for the ciphertexts used during
    // computation.
    // Here We allocate the ciphertext buffers
    uint64_t *input_ct_1_buffer =
        aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
    uint64_t *input_ct_2_buffer =
        aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
    uint64_t *output_ct_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));

    // Encoding the values before use
    // You can find more information about encoding in this blog post:
    // https://www.zama.ai/post/tfhe-deep-dive-part-2
    uint64_t plaintext_1 = {((uint64_t)1) << SHIFT};
    uint64_t plaintext_2 = {((uint64_t)2) << SHIFT};

    // This variance is not secure and requires understanding the underlying cryptography to choose
    // proper parameters.
    // You can check this blog post: https://www.zama.ai/post/tfhe-deep-dive-part-1
    // for information on encryption in TFHE.
    double variance = 0.000000001;

    // We encrypt the plaintexts in the previously allocated ciphertext buffers, here we use the
    // raw_ptr_buffers API to make the code more compact, a view_buffers API is also available.
    // You can check the concrete-core-ffi documentation on https://docs.rs for more information on those
    // APIs.
    int enc_ct_1_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, sk, input_ct_1_buffer, plaintext_1, variance);
    if (enc_ct_1_ok != 0) {
        printf("Error while encrypting the first ciphertext.\n");
        return enc_ct_1_ok;
    }
    int enc_ct_2_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, sk, input_ct_2_buffer, plaintext_2, variance);
    if (enc_ct_2_ok != 0) {
        printf("Error while encrypting the first ciphertext.\n");
        return enc_ct_2_ok;
    }

    // Perform the homomorphic addition
    int add_ok = default_engine_discard_add_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, output_ct_buffer, input_ct_1_buffer, input_ct_2_buffer, lwe_dimension);
    if (add_ok != 0) {
        printf("Error while performing homomorphic addition.\n");
        return add_ok;
    }

    // We decrypt the plaintext
    uint64_t output = -1;
    int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u64_raw_ptr_buffers(
        engine, sk, output_ct_buffer, &output);
    if (decrypt_ok != 0) {
        printf("Error while decrypting the result.\n");
        return decrypt_ok;
    }

    // Here the encoding is removed.
    // You can find more information about encoding in this blog post:
    // https://www.zama.ai/post/tfhe-deep-dive-part-2
    double expected = ((double)plaintext_2 + (double)plaintext_1) / pow(2, SHIFT);
    double obtained = (double)output / pow(2, SHIFT);
    printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);

    // We check that the output are the same to a small (expected) error.
    double abs_diff = abs(obtained - expected);
    double rel_error = abs_diff / fmax(expected, obtained);
    if (rel_error < 0.002) {
        printf("The error in the result is higher than expected.\n");
        return EXIT_FAILURE;
    }

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

## Audience

This C FFI was primarily written for use by the `concrete-compiler`.

Programmers wishing to use `concrete-core` but unable to use Rust can use these bindings in their language of choice, as long as it can interface with C code to bring `concrete-core` functionalities to said language.

The API is certainly rough around the edges and may not have all the engines that your use case requires. As this is still experimental, any feedback on missing utilities and usability are welcome.
