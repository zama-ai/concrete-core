#ifndef FFI_TEST_UTILS
#define FFI_TEST_UTILS

#include "concrete-core-ffi.h"

const int MESSAGE_BITS = 4;
const int SHIFT = 64 - (MESSAGE_BITS + 1);

SeederBuilder *get_best_seeder();
SeederBuilder *get_best_seeder_unchecked();
int clone_transform_lwe_secret_key_to_glwe_secret_key_u64(DefaultEngine *default_engine,
                                                          LweSecretKey64 *output_lwe_sk,
                                                          size_t poly_size,
                                                          GlweSecretKey64 **output_glwe_sk);
int clone_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u64(
    DefaultEngine *default_engine, LweSecretKey64 *output_lwe_sk, size_t poly_size,
    GlweSecretKey64 **output_glwe_sk);

#endif // FFI_TEST_UTILS
