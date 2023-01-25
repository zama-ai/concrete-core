#include "concrete-core-ffi.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void extract_bits_view_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine(&fft_engine);
  assert(fft_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_small_dimension = 585;

  size_t level_bsk = 2;
  size_t base_log_bsk = 10;

  size_t level_ksk = 7;
  size_t base_log_ksk = 4;

  double var = powl(2.0, -120);

  size_t number_of_bits_of_message = 5;

  // We generate the keys
  LweSecretKey32 *lwe_small_sk = NULL;
  int lwe_small_sk_ok = default_engine_generate_new_lwe_secret_key_u32(
      default_engine, lwe_small_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  GlweSecretKey32 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_u32(default_engine, glwe_dimension,
                                                                   polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_u32(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var, &bsk);
  assert(bsk_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_u32(
      fft_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;

  LweSecretKey32 *lwe_big_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok =
      clone_transform_glwe_secret_key_to_lwe_secret_key_u32(default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey32 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u32(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  uint32_t delta_log = 32 - number_of_bits_of_message;

  // 19 in binary is 10011, so has the high bit, low bit set and is not symetrical
  uint32_t val = 19;
  uint32_t message = val << delta_log;

  // We will extract all bits
  size_t number_of_bits_to_extract = number_of_bits_of_message;

  uint32_t *lwe_in_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_big_dimension + 1));

  LweCiphertextMutView32 *lwe_in_as_mut_view = NULL;
  int lwe_in_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_u32(
      default_engine, lwe_in_buffer, lwe_big_dimension + 1, &lwe_in_as_mut_view);
  assert(lwe_in_mut_view_ok == 0);

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u32_view_buffers(
      default_engine, lwe_big_sk, lwe_in_as_mut_view, message, var);
  assert(encrypt_ok == 0);

  LweCiphertextView32 *lwe_in_as_view = NULL;
  int lwe_in_view_ok = default_engine_create_lwe_ciphertext_view_from_u32(
      default_engine, lwe_in_buffer, lwe_big_dimension + 1, &lwe_in_as_view);
  assert(lwe_in_view_ok == 0);

  {
    uint32_t output = -1;
    int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u32_view_buffers(
        default_engine, lwe_big_sk, lwe_in_as_view, &output);
    assert(decrypt_ok == 0);

    uint32_t rounded = closest_representable(output, 1, 5);
    uint32_t decrypted = rounded >> delta_log;
    printf("sanity check %" PRIu32 "\n", decrypted);
  }

  uint32_t *lwe_list_out_buffer = aligned_alloc(
      U32_ALIGNMENT, sizeof(uint32_t) * (lwe_small_dimension + 1) * number_of_bits_to_extract);

  LweCiphertextVectorMutView32 *lwe_list_out_as_mut_view = NULL;
  int lwe_out_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_u32(
      default_engine, lwe_list_out_buffer, lwe_small_dimension + 1, number_of_bits_to_extract,
      &lwe_list_out_as_mut_view);
  assert(lwe_out_mut_view_ok == 0);

  int extract_bits_ok = fft_engine_lwe_ciphertext_discarding_bit_extraction_u32_view_buffers(
      fft_engine, fbsk, ksk_lwe_big_to_small, lwe_list_out_as_mut_view, lwe_in_as_view,
      number_of_bits_to_extract, delta_log);

  assert(extract_bits_ok == 0);

  LweCiphertextVectorView32 *lwe_list_out_as_view = NULL;
  int lwe_out_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_u32(
      default_engine, lwe_list_out_buffer, lwe_small_dimension + 1, number_of_bits_to_extract,
      &lwe_list_out_as_view);
  assert(lwe_out_view_ok == 0);

  uint32_t *output_plaintext_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * number_of_bits_to_extract);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    output_plaintext_buffer[idx] = 0;
  }

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u32_view_buffers(
      default_engine, lwe_small_sk, lwe_list_out_as_view, output_plaintext_buffer);

  assert(decrypt_ok == 0);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    uint32_t expected = (val >> (number_of_bits_of_message - 1 - idx)) & 1;
    uint32_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint32_t decrypted = rounded >> 31;
    printf("decrypted %" PRIu32 ", expected %" PRIu32 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  destroy_lwe_ciphertext_vector_mut_view_u32(lwe_list_out_as_mut_view);
  destroy_lwe_ciphertext_view_u32(lwe_in_as_view);
  destroy_lwe_ciphertext_mut_view_u32(lwe_in_as_mut_view);
  destroy_lwe_keyswitch_key_u32(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_u32(lwe_big_sk);
  destroy_fft_fourier_lwe_bootstrap_key_u32(fbsk);
  destroy_lwe_bootstrap_key_u32(bsk);
  destroy_glwe_secret_key_u32(glwe_sk);
  destroy_lwe_secret_key_u32(lwe_small_sk);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_fft_engine(fft_engine);
  destroy_seeder_builder(builder);
  free(lwe_in_buffer);
  free(lwe_list_out_buffer);
  free(output_plaintext_buffer);
}

void extract_bits_unchecked_view_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine_unchecked(&fft_engine);
  assert(fft_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_small_dimension = 585;

  size_t level_bsk = 2;
  size_t base_log_bsk = 10;

  size_t level_ksk = 7;
  size_t base_log_ksk = 4;

  double var = powl(2.0, -120);

  size_t number_of_bits_of_message = 5;

  // We generate the keys
  LweSecretKey32 *lwe_small_sk = NULL;
  int lwe_small_sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(
      default_engine, lwe_small_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  GlweSecretKey32 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_unchecked_u32(
      default_engine, glwe_dimension, polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_unchecked_u32(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var, &bsk);
  assert(bsk_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_unchecked_u32(
      fft_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;

  LweSecretKey32 *lwe_big_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u32(
      default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey32 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u32(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  uint32_t delta_log = 32 - number_of_bits_of_message;

  // 19 in binary is 10011, so has the high bit, low bit set and is not symetrical
  uint32_t val = 19;
  uint32_t message = val << delta_log;

  // We will extract all bits
  size_t number_of_bits_to_extract = number_of_bits_of_message;

  uint32_t *lwe_in_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_big_dimension + 1));

  LweCiphertextMutView32 *lwe_in_as_mut_view = NULL;
  int lwe_in_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_unchecked_u32(
      default_engine, lwe_in_buffer, lwe_big_dimension + 1, &lwe_in_as_mut_view);
  assert(lwe_in_mut_view_ok == 0);

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u32_view_buffers(
      default_engine, lwe_big_sk, lwe_in_as_mut_view, message, var);
  assert(encrypt_ok == 0);

  LweCiphertextView32 *lwe_in_as_view = NULL;
  int lwe_in_view_ok = default_engine_create_lwe_ciphertext_view_from_unchecked_u32(
      default_engine, lwe_in_buffer, lwe_big_dimension + 1, &lwe_in_as_view);
  assert(lwe_in_view_ok == 0);

  {
    uint32_t output = -1;
    int decrypt_ok = default_engine_decrypt_lwe_ciphertext_unchecked_u32_view_buffers(
        default_engine, lwe_big_sk, lwe_in_as_view, &output);
    assert(decrypt_ok == 0);

    uint32_t rounded = closest_representable(output, 1, 5);
    uint32_t decrypted = rounded >> delta_log;
    printf("sanity check %" PRIu32 "\n", decrypted);
  }

  uint32_t *lwe_list_out_buffer = aligned_alloc(
      U32_ALIGNMENT, sizeof(uint32_t) * (lwe_small_dimension + 1) * number_of_bits_to_extract);

  LweCiphertextVectorMutView32 *lwe_list_out_as_mut_view = NULL;
  int lwe_out_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_unchecked_u32(
      default_engine, lwe_list_out_buffer, lwe_small_dimension + 1, number_of_bits_to_extract,
      &lwe_list_out_as_mut_view);
  assert(lwe_out_mut_view_ok == 0);

  int extract_bits_ok =
      fft_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u32_view_buffers(
          fft_engine, fbsk, ksk_lwe_big_to_small, lwe_list_out_as_mut_view, lwe_in_as_view,
          number_of_bits_to_extract, delta_log);

  assert(extract_bits_ok == 0);

  LweCiphertextVectorView32 *lwe_list_out_as_view = NULL;
  int lwe_out_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_unchecked_u32(
      default_engine, lwe_list_out_buffer, lwe_small_dimension + 1, number_of_bits_to_extract,
      &lwe_list_out_as_view);
  assert(lwe_out_view_ok == 0);

  uint32_t *output_plaintext_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * number_of_bits_to_extract);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    output_plaintext_buffer[idx] = 0;
  }

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u32_view_buffers(
      default_engine, lwe_small_sk, lwe_list_out_as_view, output_plaintext_buffer);

  assert(decrypt_ok == 0);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    uint32_t expected = (val >> (number_of_bits_of_message - 1 - idx)) & 1;
    uint32_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint32_t decrypted = rounded >> 31;
    printf("decrypted %" PRIu32 ", expected %" PRIu32 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  destroy_lwe_ciphertext_vector_mut_view_unchecked_u32(lwe_list_out_as_mut_view);
  destroy_lwe_ciphertext_view_unchecked_u32(lwe_in_as_view);
  destroy_lwe_ciphertext_mut_view_unchecked_u32(lwe_in_as_mut_view);
  destroy_lwe_keyswitch_key_unchecked_u32(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_unchecked_u32(lwe_big_sk);
  destroy_fft_fourier_lwe_bootstrap_key_unchecked_u32(fbsk);
  destroy_lwe_bootstrap_key_unchecked_u32(bsk);
  destroy_glwe_secret_key_unchecked_u32(glwe_sk);
  destroy_lwe_secret_key_unchecked_u32(lwe_small_sk);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fft_engine_unchecked(fft_engine);
  destroy_seeder_builder_unchecked(builder);
  free(lwe_in_buffer);
  free(lwe_list_out_buffer);
  free(output_plaintext_buffer);
}

void extract_bits_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine(&fft_engine);
  assert(fft_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_small_dimension = 585;

  size_t level_bsk = 2;
  size_t base_log_bsk = 10;

  size_t level_ksk = 7;
  size_t base_log_ksk = 4;

  double var = powl(2.0, -120);

  size_t number_of_bits_of_message = 5;

  // We generate the keys
  LweSecretKey32 *lwe_small_sk = NULL;
  int lwe_small_sk_ok = default_engine_generate_new_lwe_secret_key_u32(
      default_engine, lwe_small_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  GlweSecretKey32 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_u32(default_engine, glwe_dimension,
                                                                   polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_u32(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var, &bsk);
  assert(bsk_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_u32(
      fft_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;

  LweSecretKey32 *lwe_big_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok =
      clone_transform_glwe_secret_key_to_lwe_secret_key_u32(default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey32 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u32(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  uint32_t delta_log = 32 - number_of_bits_of_message;

  // 19 in binary is 10011, so has the high bit, low bit set and is not symetrical
  uint32_t val = 19;
  uint32_t message = val << delta_log;

  // We will extract all bits
  size_t number_of_bits_to_extract = number_of_bits_of_message;

  uint32_t *lwe_in_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_big_dimension + 1));

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u32_raw_ptr_buffers(
      default_engine, lwe_big_sk, lwe_in_buffer, message, var);
  assert(encrypt_ok == 0);

  {
    uint32_t output = -1;
    int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u32_raw_ptr_buffers(
        default_engine, lwe_big_sk, lwe_in_buffer, &output);
    assert(decrypt_ok == 0);

    uint32_t rounded = closest_representable(output, 1, 5);
    uint32_t decrypted = rounded >> delta_log;
    printf("sanity check %" PRIu32 "\n", decrypted);
  }

  uint32_t *lwe_list_out_buffer = aligned_alloc(
      U32_ALIGNMENT, sizeof(uint32_t) * (lwe_small_dimension + 1) * number_of_bits_to_extract);

  int extract_bits_ok = fft_engine_lwe_ciphertext_discarding_bit_extraction_u32_raw_ptr_buffers(
      fft_engine, default_engine, fbsk, ksk_lwe_big_to_small, lwe_list_out_buffer, lwe_in_buffer,
      number_of_bits_to_extract, delta_log);

  assert(extract_bits_ok == 0);

  uint32_t *output_plaintext_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * number_of_bits_to_extract);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    output_plaintext_buffer[idx] = 0;
  }

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u32_raw_ptr_buffers(
      default_engine, lwe_small_sk, lwe_list_out_buffer, output_plaintext_buffer,
      number_of_bits_to_extract);

  assert(decrypt_ok == 0);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    uint32_t expected = (val >> (number_of_bits_of_message - 1 - idx)) & 1;
    uint32_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint32_t decrypted = rounded >> 31;
    printf("decrypted %" PRIu32 ", expected %" PRIu32 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  destroy_lwe_keyswitch_key_u32(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_u32(lwe_big_sk);
  destroy_fft_fourier_lwe_bootstrap_key_u32(fbsk);
  destroy_lwe_bootstrap_key_u32(bsk);
  destroy_glwe_secret_key_u32(glwe_sk);
  destroy_lwe_secret_key_u32(lwe_small_sk);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_fft_engine(fft_engine);
  destroy_seeder_builder(builder);
  free(lwe_in_buffer);
  free(lwe_list_out_buffer);
  free(output_plaintext_buffer);
}

void extract_bits_unchecked_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine_unchecked(&fft_engine);
  assert(fft_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_small_dimension = 585;

  size_t level_bsk = 2;
  size_t base_log_bsk = 10;

  size_t level_ksk = 7;
  size_t base_log_ksk = 4;

  double var = powl(2.0, -120);

  size_t number_of_bits_of_message = 5;

  // We generate the keys
  LweSecretKey32 *lwe_small_sk = NULL;
  int lwe_small_sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(
      default_engine, lwe_small_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  GlweSecretKey32 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_unchecked_u32(
      default_engine, glwe_dimension, polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_unchecked_u32(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var, &bsk);
  assert(bsk_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_unchecked_u32(
      fft_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;

  LweSecretKey32 *lwe_big_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u32(
      default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey32 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u32(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  uint32_t delta_log = 32 - number_of_bits_of_message;

  // 19 in binary is 10011, so has the high bit, low bit set and is not symetrical
  uint32_t val = 19;
  uint32_t message = val << delta_log;

  // We will extract all bits
  size_t number_of_bits_to_extract = number_of_bits_of_message;

  uint32_t *lwe_in_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_big_dimension + 1));

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u32_raw_ptr_buffers(
      default_engine, lwe_big_sk, lwe_in_buffer, message, var);
  assert(encrypt_ok == 0);

  {
    uint32_t output = -1;
    int decrypt_ok = default_engine_decrypt_lwe_ciphertext_unchecked_u32_raw_ptr_buffers(
        default_engine, lwe_big_sk, lwe_in_buffer, &output);
    assert(decrypt_ok == 0);

    uint32_t rounded = closest_representable(output, 1, 5);
    uint32_t decrypted = rounded >> delta_log;
    printf("sanity check %" PRIu32 "\n", decrypted);
  }

  uint32_t *lwe_list_out_buffer = aligned_alloc(
      U32_ALIGNMENT, sizeof(uint32_t) * (lwe_small_dimension + 1) * number_of_bits_to_extract);

  int extract_bits_ok =
      fft_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u32_raw_ptr_buffers(
          fft_engine, default_engine, fbsk, ksk_lwe_big_to_small, lwe_list_out_buffer,
          lwe_in_buffer, number_of_bits_to_extract, delta_log);

  assert(extract_bits_ok == 0);

  uint32_t *output_plaintext_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * number_of_bits_to_extract);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    output_plaintext_buffer[idx] = 0;
  }

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u32_raw_ptr_buffers(
      default_engine, lwe_small_sk, lwe_list_out_buffer, output_plaintext_buffer,
      number_of_bits_to_extract);

  assert(decrypt_ok == 0);

  for (size_t idx = 0; idx < number_of_bits_to_extract; ++idx) {
    uint32_t expected = (val >> (number_of_bits_of_message - 1 - idx)) & 1;
    uint32_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint32_t decrypted = rounded >> 31;
    printf("decrypted %" PRIu32 ", expected %" PRIu32 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  destroy_lwe_keyswitch_key_unchecked_u32(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_unchecked_u32(lwe_big_sk);
  destroy_fft_fourier_lwe_bootstrap_key_unchecked_u32(fbsk);
  destroy_lwe_bootstrap_key_unchecked_u32(bsk);
  destroy_glwe_secret_key_unchecked_u32(glwe_sk);
  destroy_lwe_secret_key_unchecked_u32(lwe_small_sk);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fft_engine_unchecked(fft_engine);
  destroy_seeder_builder_unchecked(builder);
  free(lwe_in_buffer);
  free(lwe_list_out_buffer);
  free(output_plaintext_buffer);
}

int main(void) {
  extract_bits_view_buffers_test();
  extract_bits_unchecked_view_buffers_test();
  extract_bits_raw_ptr_buffers_test();
  extract_bits_unchecked_raw_ptr_buffers_test();
  return EXIT_SUCCESS;
}
