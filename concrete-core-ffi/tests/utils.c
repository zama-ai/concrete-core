#include "concrete-core-ffi.h"
#include <assert.h>
#include <stdio.h>

SeederBuilder *get_best_seeder() {
  SeederBuilder *builder = NULL;
#if defined(__x86_64__) || defined(_M_X64)
  bool rdseed_seeder_available = false;
  int rdseed_seeder_available_ok = rdseed_seeder_is_available(&rdseed_seeder_available);
  assert(rdseed_seeder_available_ok == 0);

  if (rdseed_seeder_available) {
    int get_builder_ok = get_rdseed_seeder_builder(&builder);
    assert(get_builder_ok == 0);
    printf("Using rdseed seeder.\n");
    return builder;
  }
#endif

#if defined(__APPLE__)
  bool apple_secure_enclave_seeder_available = false;
  int apple_secure_enclave_seeder_available_ok =
      apple_secure_enclave_seeder_is_available(&apple_secure_enclave_seeder_available);
  assert(apple_secure_enclave_seeder_available_ok == 0);

  if (apple_secure_enclave_seeder_available) {
    int get_builder_ok = get_apple_secure_enclave_seeder_builder(&builder);
    assert(get_builder_ok == 0);
    printf("Using Apple secure enclave seeder.\n");
    return builder;
  }
#endif

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
#if defined(__x86_64__) || defined(_M_X64)
  bool rdseed_seeder_available = false;
  int rdseed_seeder_available_ok = rdseed_seeder_is_available_unchecked(&rdseed_seeder_available);
  assert(rdseed_seeder_available_ok == 0);

  if (rdseed_seeder_available) {
    int get_builder_ok = get_rdseed_seeder_builder_unchecked(&builder);
    assert(get_builder_ok == 0);
    printf("Using rdseed seeder.\n");
    return builder;
  }
#endif

#if defined(__APPLE__)
  bool apple_secure_enclave_seeder_available = false;
  int apple_secure_enclave_seeder_available_ok =
      apple_secure_enclave_seeder_is_available_unchecked(&apple_secure_enclave_seeder_available);
  assert(apple_secure_enclave_seeder_available_ok == 0);

  if (apple_secure_enclave_seeder_available) {
    int get_builder_ok = get_apple_secure_enclave_seeder_builder_unchecked(&builder);
    assert(get_builder_ok == 0);
    printf("Using Apple secure enclave seeder.\n");
    return builder;
  }
#endif

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
    DefaultEngine *default_engine, GlweSecretKey64 *input_glwe_sk, LweSecretKey64 **output_lwe_sk) {
  GlweSecretKey64 *input_glwe_sk_clone = NULL;
  int glwe_in_sk_clone_ok =
      clone_glwe_secret_key_unchecked_u64(input_glwe_sk, &input_glwe_sk_clone);
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

uint64_t closest_representable(uint64_t input, uint64_t level_count, uint64_t base_log) {
  // The closest number representable by the decomposition can be computed by performing
  // the rounding at the appropriate bit.

  // We compute the number of least significant bits which can not be represented by the
  // decomposition
  uint64_t non_rep_bit_count = (uint64_t)64 - (level_count * base_log);
  // We generate a mask which captures the non representable bits
  uint64_t non_rep_mask = (uint64_t)1 << (non_rep_bit_count - 1);
  // We retrieve the non representable bits
  uint64_t non_rep_bits = input & non_rep_mask;
  // We extract the msb of the  non representable bits to perform the rounding
  uint64_t non_rep_msb = non_rep_bits >> (non_rep_bit_count - (uint64_t)1);
  // We remove the non-representable bits and perform the rounding
  uint64_t res = input >> non_rep_bit_count;
  res = res + non_rep_msb;
  return res << non_rep_bit_count;
}
