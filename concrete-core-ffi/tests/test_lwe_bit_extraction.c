#include "concrete-core-ffi.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void extract_bits_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftwEngine *fftw_engine = NULL;

  int fftw_engine_ok = new_fftw_engine(&fftw_engine);
  assert(fftw_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double keyswitch_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t input_lwe_dimension = glwe_dimension * poly_size;
  size_t output_lwe_dimension = 20;
  size_t extracted_bits_count = 1;
  size_t delta_log = 63;

  // We generate the keys
  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey64 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_u64(
      default_engine, glwe_dimension, poly_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweSecretKey64 *input_lwe_sk = NULL;
  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_glwe_secret_key_to_lwe_secret_key_u64(
      default_engine, glwe_sk, &input_lwe_sk);
  assert(clone_transform_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_u64(
      default_parallel_engine, output_lwe_sk, glwe_sk, base_log, level, pbs_variance,
      &bsk);
  assert(bsk_ok == 0);

  LweKeyswitchKey64 *ksk = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u64(
      default_engine, input_lwe_sk, output_lwe_sk, level, base_log, keyswitch_variance, &ksk);
  assert(ksk_ok == 0);

  FftwFourierLweBootstrapKey64 *fbsk = NULL;
  int fbsk_ok = fftw_engine_convert_lwe_bootstrap_key_to_fftw_fourier_lwe_bootstrap_key_u64(
      fftw_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  // We generate the ciphertexts
  uint64_t *input_ct_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (input_lwe_dimension + 1));
  uint64_t *output_ct_vector_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (output_lwe_dimension + 1) * extracted_bits_count);
  uint64_t plaintext = ((uint64_t)1) << delta_log;

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
      default_engine, input_lwe_sk, input_ct_buffer, plaintext, encryption_variance);
  assert(encrypt_ok == 0);

  // We perform the bit extraction
  int result_ok = fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_raw_ptr_buffers(
      fftw_engine, default_engine, fbsk, ksk, output_ct_vector_buffer, input_ct_buffer, 
      extracted_bits_count, delta_log);
  assert(result_ok == 0);

  // Since we only extract one bit the output is a single value
  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u64_raw_ptr_buffers(
      default_engine, output_lwe_sk, output_ct_vector_buffer, &output, extracted_bits_count);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, delta_log);
  double obtained = (double)output / pow(2, delta_log);
  printf("Expected: %f, Obtained: %f\n", expected, obtained);
  double abs_diff = abs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.01);

  // We deallocate the objects
  destroy_lwe_secret_key_u64(input_lwe_sk);
  destroy_lwe_secret_key_u64(output_lwe_sk);
  destroy_glwe_secret_key_u64(glwe_sk);
  destroy_lwe_bootstrap_key_u64(bsk);
  destroy_lwe_keyswitch_key_u64(ksk);
  destroy_fftw_fourier_lwe_bootstrap_key_u64(fbsk);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_fftw_engine(fftw_engine);
  destroy_seeder_builder(builder);
  free(input_ct_buffer);
  free(output_ct_vector_buffer);
}


void extract_bits_unchecked_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftwEngine *fftw_engine = NULL;

  int fftw_engine_ok = new_fftw_engine_unchecked(&fftw_engine);
  assert(fftw_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double keyswitch_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t input_lwe_dimension = glwe_dimension * poly_size;
  size_t output_lwe_dimension = 20;
  size_t extracted_bits_count = 1;
  size_t delta_log = 63;

  // We generate the keys
  LweSecretKey64 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey64 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_unchecked_u64(
      default_engine, glwe_dimension, poly_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweSecretKey64 *input_lwe_sk = NULL;
  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u64(
      default_engine, glwe_sk, &input_lwe_sk);
  assert(clone_transform_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_unchecked_u64(
      default_parallel_engine, output_lwe_sk, glwe_sk, base_log, level, pbs_variance,
      &bsk);
  assert(bsk_ok == 0);

  LweKeyswitchKey64 *ksk = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u64(
      default_engine, input_lwe_sk, output_lwe_sk, level, base_log, keyswitch_variance, &ksk);
  assert(ksk_ok == 0);

  FftwFourierLweBootstrapKey64 *fbsk = NULL;
  int fbsk_ok = fftw_engine_convert_lwe_bootstrap_key_to_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
      fftw_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  // We generate the ciphertexts
  uint64_t *input_ct_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (input_lwe_dimension + 1));
  uint64_t *output_ct_vector_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (output_lwe_dimension + 1) * extracted_bits_count);
  uint64_t plaintext = ((uint64_t)1) << delta_log;

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
      default_engine, input_lwe_sk, input_ct_buffer, plaintext, encryption_variance);
  assert(encrypt_ok == 0);

  // We perform the bit extraction
  int result_ok = fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_raw_ptr_buffers(
      fftw_engine, default_engine, fbsk, ksk, output_ct_vector_buffer, input_ct_buffer,
      extracted_bits_count, delta_log);
  assert(result_ok == 0);

  // Since we only extract one bit the output is a single value
  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u64_raw_ptr_buffers(
      default_engine, output_lwe_sk, output_ct_vector_buffer, &output, extracted_bits_count);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, delta_log);
  double obtained = (double)output / pow(2, delta_log);
  printf("Expected: %f, Obtained: %f\n", expected, obtained);
  double abs_diff = abs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.01);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u64(input_lwe_sk);
  destroy_lwe_secret_key_unchecked_u64(output_lwe_sk);
  destroy_glwe_secret_key_unchecked_u64(glwe_sk);
  destroy_lwe_bootstrap_key_unchecked_u64(bsk);
  destroy_lwe_keyswitch_key_unchecked_u64(ksk);
  destroy_fftw_fourier_lwe_bootstrap_key_unchecked_u64(fbsk);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fftw_engine_unchecked(fftw_engine);
  destroy_seeder_builder_unchecked(builder);
  free(input_ct_buffer);
  free(output_ct_vector_buffer);
}

int main(void) {
  extract_bits_raw_ptr_buffers_test();
  extract_bits_unchecked_raw_ptr_buffers_test();
  return EXIT_SUCCESS;
}
