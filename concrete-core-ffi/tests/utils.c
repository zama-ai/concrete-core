#include "concrete-core-ffi.h"
#include <assert.h>
#include <stdio.h>

SeederBuilder *get_best_seeder() {
  SeederBuilder *builder = NULL;
  bool rdseed_seeder_available = false;
  int rdseed_seeder_available_ok = rdseed_seeder_is_available(&rdseed_seeder_available);
  assert(rdseed_seeder_available_ok == 0);

  if (rdseed_seeder_available) {
    int get_builder_ok = get_rdseed_seeder_builder(&builder);
    assert(get_builder_ok == 0);
    printf("Using rdseed seeder.\n");
    return builder;
  }

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
    printf("Using Unix seeder.\n");
    return builder;
  }

  printf("No available seeder.\n");
  return builder;
}

SeederBuilder *get_best_seeder_unchecked() {
  SeederBuilder *builder = NULL;
  bool rdseed_seeder_available = false;
  int rdseed_seeder_available_ok = rdseed_seeder_is_available_unchecked(&rdseed_seeder_available);
  assert(rdseed_seeder_available_ok == 0);

  if (rdseed_seeder_available) {
    int get_builder_ok = get_rdseed_seeder_builder_unchecked(&builder);
    assert(get_builder_ok == 0);
    printf("Using rdseed seeder.\n");
    return builder;
  }

  bool unix_seeder_available = false;
  int unix_seeder_available_ok = unix_seeder_is_available_unchecked(&unix_seeder_available);
  assert(unix_seeder_available_ok == 0);

  if (unix_seeder_available) {
    // DANGER DANGER DANGER DANGER DANGER DANGER
    // HIGHLY UNSAFE ONLY FOR TESTING PURPOSES
    uint64_t secret_high_64 = 0;
    uint64_t secret_low_64 = 0;
    int get_builder_ok = get_unix_seeder_builder_unchecked(secret_high_64, secret_low_64, &builder);
    assert(get_builder_ok == 0);
    printf("Using Unix seeder.\n");
    return builder;
  }

  printf("No available seeder.\n");
  return builder;
}

// This is not part of the C FFI but rather is a C util exposed for convenience in tests.
int clone_transform_lwe_secret_key_to_glwe_secret_key_u64(DefaultEngine *default_engine,
                                                          LweSecretKey64 *input_lwe_sk,
                                                          size_t poly_size,
                                                          GlweSecretKey64 **output_glwe_sk) {
  LweSecretKey64 *input_lwe_sk_clone = NULL;
  int lwe_in_sk_clone_ok = clone_lwe_secret_key_u64(input_lwe_sk, &input_lwe_sk_clone);
  if (lwe_in_sk_clone_ok != 0) {
    return 1;
  }

  int glwe_sk_ok = default_engine_transform_lwe_secret_key_to_glwe_secret_key_u64(
      default_engine, &input_lwe_sk_clone, poly_size, output_glwe_sk);
  if (glwe_sk_ok != 0) {
    return 1;
  }

  if (input_lwe_sk_clone != NULL) {
    return 1;
  }

  return 0;
}

// This is not part of the C FFI but rather is a C util exposed for convenience in tests.
int clone_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u64(
    DefaultEngine *default_engine, LweSecretKey64 *input_lwe_sk, size_t poly_size,
    GlweSecretKey64 **output_glwe_sk) {
  LweSecretKey64 *input_lwe_sk_clone = NULL;
  int lwe_in_sk_clone_ok = clone_lwe_secret_key_unchecked_u64(input_lwe_sk, &input_lwe_sk_clone);
  if (lwe_in_sk_clone_ok != 0) {
    return 1;
  }

  int glwe_sk_ok = default_engine_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u64(
      default_engine, &input_lwe_sk_clone, poly_size, output_glwe_sk);
  if (glwe_sk_ok != 0) {
    return 1;
  }

  if (input_lwe_sk_clone != NULL) {
    return 1;
  }

  return 0;
}

// This is not part of the C FFI but rather is a C util exposed for convenience in tests.
int clone_transform_glwe_secret_key_to_lwe_secret_key_u64(DefaultEngine *default_engine,
                                                          GlweSecretKey64 *input_glwe_sk,
                                                          LweSecretKey64 **output_lwe_sk) {
  GlweSecretKey64 *input_glwe_sk_clone = NULL;
  int glwe_in_sk_clone_ok = clone_glwe_secret_key_u64(input_glwe_sk, &input_glwe_sk_clone);
  if (glwe_in_sk_clone_ok != 0) {
    return 1;
  }

  int lwe_sk_ok = default_engine_transform_glwe_secret_key_to_lwe_secret_key_u64(
      default_engine, &input_glwe_sk_clone, output_lwe_sk);
  if (lwe_sk_ok != 0) {
    return 1;
  }

  if (input_glwe_sk_clone != NULL) {
    return 1;
  }

  return 0;
}

// This is not part of the C FFI but rather is a C util exposed for convenience in tests.
int clone_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u64(
    DefaultEngine *default_engine, GlweSecretKey64 *input_glwe_sk,
    LweSecretKey64 **output_lwe_sk) {
  GlweSecretKey64 *input_glwe_sk_clone = NULL;
  int glwe_in_sk_clone_ok = clone_glwe_secret_key_unchecked_u64(input_glwe_sk, 
                                                                &input_glwe_sk_clone);
  if (glwe_in_sk_clone_ok != 0) {
    return 1;
  }

  int lwe_sk_ok = default_engine_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u64(
      default_engine, &input_glwe_sk_clone, output_lwe_sk);
  if (lwe_sk_ok != 0) {
    return 1;
  }

  if (input_glwe_sk_clone != NULL) {
    return 1;
  }

  return 0;
}
