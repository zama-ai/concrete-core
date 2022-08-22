#include "concrete-core-ffi.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void bootstrap_key_to_mut_view_conversion_view_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t glwe_size = glwe_dimension + 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey64 *input_lwe_sk = NULL;
  int lwe_in_key_ok =
      default_engine_create_lwe_secret_key_u64(default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_create_lwe_secret_key_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey64 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_u64(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweBootstrapKey64 *standard_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_create_lwe_bootstrap_key_u64(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &standard_bsk);
  assert(seeded_bsk_ok == 0);

  // Allocate memory for the bootstrap key mut view
  size_t bsk_buffer_len = input_lwe_dimension * glwe_size * glwe_size * poly_size * level;
  uint64_t *bootstrap_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * bsk_buffer_len);

  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    bootstrap_key_mut_mem[idx] = 0;
  }

  LweBootstrapKeyMutView64 *standard_bsk_mut_view = NULL;
  int bsk_mut_view_ok = default_engine_construct_lwe_bootstrap_key_mut_view_u64(
      default_engine, bootstrap_key_mut_mem, input_lwe_dimension, glwe_size, poly_size, base_log,
      level, &standard_bsk_mut_view);
  assert(bsk_mut_view_ok == 0);

  int bsk_to_bsk_mut_view_conversion =
      default_engine_discard_convert_lwe_bootstrap_key_to_lwe_bootstrap_key_mut_view_u64_view_buffers(
          default_engine, standard_bsk, standard_bsk_mut_view);
  assert(bsk_to_bsk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    if (bootstrap_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_u64(input_lwe_sk);
  destroy_lwe_secret_key_u64(output_lwe_sk);
  destroy_glwe_secret_key_u64(output_glwe_sk);
  destroy_lwe_bootstrap_key_u64(standard_bsk);
  destroy_lwe_bootstrap_key_mut_view_u64(standard_bsk_mut_view);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_seeder_builder(builder);
  free(bootstrap_key_mut_mem);
}

void bootstrap_key_to_mut_view_conversion_unchecked_view_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t glwe_size = glwe_dimension + 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey64 *input_lwe_sk = NULL;
  int lwe_in_key_ok = default_engine_create_lwe_secret_key_unchecked_u64(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_create_lwe_secret_key_unchecked_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey64 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u64(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweBootstrapKey64 *standard_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_create_lwe_bootstrap_key_unchecked_u64(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &standard_bsk);
  assert(seeded_bsk_ok == 0);

  // Allocate memory for the bootstrap key mut view
  size_t bsk_buffer_len = input_lwe_dimension * glwe_size * glwe_size * poly_size * level;
  uint64_t *bootstrap_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * bsk_buffer_len);

  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    bootstrap_key_mut_mem[idx] = 0;
  }

  LweBootstrapKeyMutView64 *standard_bsk_mut_view = NULL;
  int bsk_mut_view_ok = default_engine_construct_lwe_bootstrap_key_mut_view_unchecked_u64(
      default_engine, bootstrap_key_mut_mem, input_lwe_dimension, glwe_size, poly_size, base_log,
      level, &standard_bsk_mut_view);
  assert(bsk_mut_view_ok == 0);

  int bsk_to_bsk_mut_view_conversion =
      default_engine_discard_convert_lwe_bootstrap_key_to_lwe_bootstrap_key_mut_view_unchecked_u64_view_buffers(
          default_engine, standard_bsk, standard_bsk_mut_view);
  assert(bsk_to_bsk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    if (bootstrap_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_unchecked_u64(input_lwe_sk);
  destroy_lwe_secret_key_unchecked_u64(output_lwe_sk);
  destroy_glwe_secret_key_unchecked_u64(output_glwe_sk);
  destroy_lwe_bootstrap_key_unchecked_u64(standard_bsk);
  destroy_lwe_bootstrap_key_mut_view_unchecked_u64(standard_bsk_mut_view);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_seeder_builder_unchecked(builder);
  free(bootstrap_key_mut_mem);
}

void bootstrap_key_to_mut_view_conversion_raw_ptr_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t glwe_size = glwe_dimension + 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey64 *input_lwe_sk = NULL;
  int lwe_in_key_ok =
      default_engine_create_lwe_secret_key_u64(default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_create_lwe_secret_key_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey64 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_u64(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweBootstrapKey64 *standard_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_create_lwe_bootstrap_key_u64(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &standard_bsk);
  assert(seeded_bsk_ok == 0);

  // Allocate memory for the bootstrap key mut view
  size_t bsk_buffer_len = input_lwe_dimension * glwe_size * glwe_size * poly_size * level;
  uint64_t *bootstrap_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * bsk_buffer_len);

  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    bootstrap_key_mut_mem[idx] = 0;
  }

  int bsk_to_bsk_mut_view_conversion =
      default_engine_discard_convert_lwe_bootstrap_key_to_lwe_bootstrap_key_mut_view_u64_raw_ptr_buffers(
          default_engine, standard_bsk, bootstrap_key_mut_mem);
  assert(bsk_to_bsk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    if (bootstrap_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_u64(input_lwe_sk);
  destroy_lwe_secret_key_u64(output_lwe_sk);
  destroy_glwe_secret_key_u64(output_glwe_sk);
  destroy_lwe_bootstrap_key_u64(standard_bsk);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_seeder_builder(builder);
  free(bootstrap_key_mut_mem);
}

void bootstrap_key_to_mut_view_conversion_unchecked_raw_ptr_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t glwe_size = glwe_dimension + 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey64 *input_lwe_sk = NULL;
  int lwe_in_key_ok = default_engine_create_lwe_secret_key_unchecked_u64(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_create_lwe_secret_key_unchecked_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey64 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u64(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweBootstrapKey64 *standard_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_create_lwe_bootstrap_key_unchecked_u64(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &standard_bsk);
  assert(seeded_bsk_ok == 0);

  // Allocate memory for the bootstrap key mut view
  size_t bsk_buffer_len = input_lwe_dimension * glwe_size * glwe_size * poly_size * level;
  uint64_t *bootstrap_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * bsk_buffer_len);

  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    bootstrap_key_mut_mem[idx] = 0;
  }

  int bsk_to_bsk_mut_view_conversion =
      default_engine_discard_convert_lwe_bootstrap_key_to_lwe_bootstrap_key_mut_view_unchecked_u64_raw_ptr_buffers(
          default_engine, standard_bsk, bootstrap_key_mut_mem);
  assert(bsk_to_bsk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < bsk_buffer_len; ++idx) {
    if (bootstrap_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_u64(input_lwe_sk);
  destroy_lwe_secret_key_u64(output_lwe_sk);
  destroy_glwe_secret_key_u64(output_glwe_sk);
  destroy_lwe_bootstrap_key_u64(standard_bsk);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_seeder_builder(builder);
  free(bootstrap_key_mut_mem);
}

int main(void) {
  bootstrap_key_to_mut_view_conversion_view_buffers();
  bootstrap_key_to_mut_view_conversion_unchecked_view_buffers();
  bootstrap_key_to_mut_view_conversion_raw_ptr_buffers();
  bootstrap_key_to_mut_view_conversion_unchecked_raw_ptr_buffers();
  return EXIT_SUCCESS;
}
