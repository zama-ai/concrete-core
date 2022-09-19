#include "concrete-core-ffi.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void keyswitch_key_to_mut_view_conversion_view_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  double ksk_variance = 0.00000000000001;
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
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_u64(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  LweKeyswitchKey64 *ksk = NULL;
  int seeded_ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u64(
      default_engine, input_lwe_sk, output_lwe_sk, level, base_log, ksk_variance, &ksk);
  assert(seeded_ksk_ok == 0);

  // Allocate memory for the keyswitch key mut view
  size_t ksk_buffer_len = input_lwe_dimension * (output_lwe_dimension + 1) * level;
  uint64_t *keyswitch_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * ksk_buffer_len);

  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    keyswitch_key_mut_mem[idx] = 0;
  }

  LweKeyswitchKeyMutView64 *ksk_mut_view = NULL;
  int ksk_mut_view_ok = default_engine_create_lwe_keyswitch_key_mut_view_from_u64(
      default_engine, keyswitch_key_mut_mem, input_lwe_dimension, output_lwe_dimension, base_log,
      level, &ksk_mut_view);
  assert(ksk_mut_view_ok == 0);

  int ksk_to_ksk_mut_view_conversion =
      default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_view_buffers(
          default_engine, ksk, ksk_mut_view);
  assert(ksk_to_ksk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    if (keyswitch_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_u64(input_lwe_sk);
  destroy_lwe_secret_key_u64(output_lwe_sk);
  destroy_lwe_keyswitch_key_u64(ksk);
  destroy_lwe_keyswitch_key_mut_view_u64(ksk_mut_view);
  destroy_default_engine(default_engine);
  destroy_seeder_builder(builder);
  free(keyswitch_key_mut_mem);
}

void keyswitch_key_to_mut_view_conversion_unchecked_view_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  double ksk_variance = 0.00000000000001;
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
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  LweKeyswitchKey64 *ksk = NULL;
  int seeded_ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u64(
      default_engine, input_lwe_sk, output_lwe_sk, level, base_log, ksk_variance, &ksk);
  assert(seeded_ksk_ok == 0);

  // Allocate memory for the keyswitch key mut view
  size_t ksk_buffer_len = input_lwe_dimension * (output_lwe_dimension + 1) * level;
  uint64_t *keyswitch_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * ksk_buffer_len);

  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    keyswitch_key_mut_mem[idx] = 0;
  }

  LweKeyswitchKeyMutView64 *ksk_mut_view = NULL;
  int ksk_mut_view_ok = default_engine_create_lwe_keyswitch_key_mut_view_from_unchecked_u64(
      default_engine, keyswitch_key_mut_mem, input_lwe_dimension, output_lwe_dimension, base_log,
      level, &ksk_mut_view);
  assert(ksk_mut_view_ok == 0);

  int ksk_to_ksk_mut_view_conversion =
      default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_unchecked_u64_view_buffers(
          default_engine, ksk, ksk_mut_view);
  assert(ksk_to_ksk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    if (keyswitch_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_unchecked_u64(input_lwe_sk);
  destroy_lwe_secret_key_unchecked_u64(output_lwe_sk);
  destroy_lwe_keyswitch_key_unchecked_u64(ksk);
  destroy_lwe_keyswitch_key_mut_view_unchecked_u64(ksk_mut_view);
  destroy_default_engine_unchecked(default_engine);
  destroy_seeder_builder_unchecked(builder);
  free(keyswitch_key_mut_mem);
}

void keyswitch_key_to_mut_view_conversion_raw_ptr_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  double ksk_variance = 0.00000000000001;
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
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_u64(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  LweKeyswitchKey64 *ksk = NULL;
  int seeded_ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u64(
      default_engine, input_lwe_sk, output_lwe_sk, level, base_log, ksk_variance, &ksk);
  assert(seeded_ksk_ok == 0);

  // Allocate memory for the keyswitch key mut view
  size_t ksk_buffer_len = input_lwe_dimension * (output_lwe_dimension + 1) * level;
  uint64_t *keyswitch_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * ksk_buffer_len);

  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    keyswitch_key_mut_mem[idx] = 0;
  }

  int ksk_to_ksk_mut_view_conversion =
      default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_raw_ptr_buffers(
          default_engine, ksk, keyswitch_key_mut_mem);
  assert(ksk_to_ksk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    if (keyswitch_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_u64(input_lwe_sk);
  destroy_lwe_secret_key_u64(output_lwe_sk);
  destroy_lwe_keyswitch_key_u64(ksk);
  destroy_default_engine(default_engine);
  destroy_seeder_builder(builder);
  free(keyswitch_key_mut_mem);
}

void keyswitch_key_to_mut_view_conversion_unchecked_raw_ptr_buffers(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  double ksk_variance = 0.00000000000001;
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
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  LweKeyswitchKey64 *ksk = NULL;
  int seeded_ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u64(
      default_engine, input_lwe_sk, output_lwe_sk, level, base_log, ksk_variance, &ksk);
  assert(seeded_ksk_ok == 0);

  // Allocate memory for the keyswitch key mut view
  size_t ksk_buffer_len = input_lwe_dimension * (output_lwe_dimension + 1) * level;
  uint64_t *keyswitch_key_mut_mem = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * ksk_buffer_len);

  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    keyswitch_key_mut_mem[idx] = 0;
  }

  int ksk_to_ksk_mut_view_conversion =
      default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_unchecked_u64_raw_ptr_buffers(
          default_engine, ksk, keyswitch_key_mut_mem);
  assert(ksk_to_ksk_mut_view_conversion == 0);

  bool mut_view_buffer_is_all_zeros = true;
  for (size_t idx = 0; idx < ksk_buffer_len; ++idx) {
    if (keyswitch_key_mut_mem[idx] != 0) {
      mut_view_buffer_is_all_zeros = false;
      break;
    }
  }

  assert(mut_view_buffer_is_all_zeros == false);

  destroy_lwe_secret_key_unchecked_u64(input_lwe_sk);
  destroy_lwe_secret_key_unchecked_u64(output_lwe_sk);
  destroy_lwe_keyswitch_key_unchecked_u64(ksk);
  destroy_default_engine_unchecked(default_engine);
  destroy_seeder_builder_unchecked(builder);
  free(keyswitch_key_mut_mem);
}

int main(void) {
  keyswitch_key_to_mut_view_conversion_view_buffers();
  keyswitch_key_to_mut_view_conversion_unchecked_view_buffers();
  keyswitch_key_to_mut_view_conversion_raw_ptr_buffers();
  keyswitch_key_to_mut_view_conversion_unchecked_raw_ptr_buffers();
  return EXIT_SUCCESS;
}
