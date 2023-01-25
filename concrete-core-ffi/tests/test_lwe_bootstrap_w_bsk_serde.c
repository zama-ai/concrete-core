#include "concrete-core-ffi.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

// This helper function expands the input LUT into output, duplicating values as needed to fill
// mega cases, taking care of the encoding and the half mega case shift in the process as well.
// All sizes should be powers of 2.
void encode_and_expand_lut(uint32_t *output, size_t output_size, size_t out_MESSAGE_BITS,
                           const uint32_t *lut, size_t lut_size) {
  assert((output_size % lut_size) == 0);

  size_t mega_case_size = output_size / lut_size;

  assert((mega_case_size % 2) == 0);

  for (size_t idx = 0; idx < mega_case_size / 2; ++idx) {
    output[idx] = lut[0] << (32 - out_MESSAGE_BITS - 1);
  }

  for (size_t idx = (lut_size - 1) * mega_case_size + mega_case_size / 2; idx < output_size;
       ++idx) {
    output[idx] = -(lut[0] << (32 - out_MESSAGE_BITS - 1));
  }

  for (size_t lut_idx = 1; lut_idx < lut_size; ++lut_idx) {
    uint32_t lut_value = lut[lut_idx] << (32 - out_MESSAGE_BITS - 1);
    size_t start = mega_case_size * (lut_idx - 1) + mega_case_size / 2;
    for (size_t output_idx = start; output_idx < start + mega_case_size; ++output_idx) {
      output[output_idx] = lut_value;
    }
  }
}

void bootstrap_view_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine(&fft_engine);
  assert(fft_engine_ok == 0);

  FftSerializationEngine *fft_serialization_engine = NULL;

  int fft_serialization_engine_ok = new_fft_serialization_engine(&fft_serialization_engine);
  assert(fft_serialization_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey32 *input_lwe_sk = NULL;
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_u32(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey32 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_u32(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey32 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_u32(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweSeededBootstrapKey32 *seeded_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_generate_new_lwe_seeded_bootstrap_key_u32(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &seeded_bsk);
  assert(seeded_bsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer seeded_bsk_buffer = {.pointer = NULL, .length = 0};
  int seeded_bsk_ser_ok = default_serialization_engine_serialize_lwe_seeded_bootstrap_key_u32(
      default_serialization_engine, seeded_bsk, &seeded_bsk_buffer);
  assert(seeded_bsk_ser_ok == 0);

  BufferView seeded_buffer_view = {.pointer = seeded_bsk_buffer.pointer,
                                   .length = seeded_bsk_buffer.length};
  LweSeededBootstrapKey32 *deser_seeded_bsk = NULL;
  int seeded_bsk_deser_ok = default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_u32(
      default_serialization_engine, seeded_buffer_view, &deser_seeded_bsk);
  assert(seeded_bsk_deser_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_engine_transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_u32(
      default_engine, &deser_seeded_bsk, &bsk);
  assert(bsk_ok == 0);

  Buffer bsk_buffer = {.pointer = NULL, .length = 0};
  int bsk_ser_ok = default_serialization_engine_serialize_lwe_bootstrap_key_u32(
      default_serialization_engine, bsk, &bsk_buffer);
  assert(bsk_ser_ok == 0);

  BufferView bsk_deser_buffer_view = {.pointer = bsk_buffer.pointer, .length = bsk_buffer.length};
  LweBootstrapKey32 *deser_bsk = NULL;
  int bsk_deser_ok = default_serialization_engine_deserialize_lwe_bootstrap_key_u32(
      default_serialization_engine, bsk_deser_buffer_view, &deser_bsk);
  assert(bsk_deser_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_u32(
      fft_engine, deser_bsk, &fbsk);
  assert(fbsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer fbsk_buffer = {.pointer = NULL, .length = 0};
  int fbsk_ser_ok = fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_u32(
      fft_serialization_engine, fbsk, &fbsk_buffer);
  assert(fbsk_ser_ok == 0);

  BufferView fbsk_buffer_view = {.pointer = fbsk_buffer.pointer, .length = fbsk_buffer.length};
  FftFourierLweBootstrapKey32 *deser_fbsk = NULL;
  int fbsk_deser_ok = fft_serialization_engine_deserialize_fft_fourier_lwe_bootstrap_key_u32(
      fft_serialization_engine, fbsk_buffer_view, &deser_fbsk);
  assert(fbsk_deser_ok == 0);

  // We generate the ciphertexts
  uint32_t *input_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (input_lwe_dimension + 1));
  uint32_t *output_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (output_lwe_dimension + 1));
  uint32_t plaintext = ((uint32_t)4) << SHIFT;

  // Here we alias the same memory regions as immutable and mutable to be able to pass it to rust
  // as writable when needed and as read-only when needed
  LweCiphertextView32 *input_ct_as_view = NULL;
  int input_ct_ok = default_engine_create_lwe_ciphertext_view_from_u32(
      default_engine, input_ct_buffer, input_lwe_dimension + 1, &input_ct_as_view);
  assert(input_ct_ok == 0);

  LweCiphertextMutView32 *input_ct_as_mut_view = NULL;
  int input_ct_as_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_u32(
      default_engine, input_ct_buffer, input_lwe_dimension + 1, &input_ct_as_mut_view);
  assert(input_ct_as_mut_view_ok == 0);

  LweCiphertextView32 *output_ct_as_view = NULL;
  int output_ct_as_view_ok = default_engine_create_lwe_ciphertext_view_from_u32(
      default_engine, output_ct_buffer, output_lwe_dimension + 1, &output_ct_as_view);
  assert(output_ct_as_view_ok == 0);

  LweCiphertextMutView32 *output_ct_as_mut_view = NULL;
  int output_ct_ok = default_engine_create_lwe_ciphertext_mut_view_from_u32(
      default_engine, output_ct_buffer, output_lwe_dimension + 1, &output_ct_as_mut_view);
  assert(output_ct_ok == 0);

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u32_view_buffers(
      default_engine, input_lwe_sk, input_ct_as_mut_view, plaintext, encryption_variance);
  assert(encrypt_ok == 0);

  int tabulation_length = 1 << MESSAGE_BITS;

  size_t accumulator_size = poly_size * (glwe_dimension + 1);

  uint32_t *accumulator = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * accumulator_size);

  uint32_t *tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * tabulation_length);
  for (int i = 0; i < tabulation_length; i++) {
    tabulated_function_array[i] = (uint32_t)i;
  }

  uint32_t *expanded_tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * poly_size);

  encode_and_expand_lut(expanded_tabulated_function_array, poly_size, MESSAGE_BITS,
                        tabulated_function_array, tabulation_length);

  GlweCiphertextView32 *accumulator_as_view = NULL;
  int accumulator_as_view_ok = default_engine_create_glwe_ciphertext_view_from_u32(
      default_engine, accumulator, accumulator_size, poly_size, &accumulator_as_view);
  assert(accumulator_as_view_ok == 0);

  GlweCiphertextMutView32 *accumulator_as_mut_view = NULL;
  int accumulator_as_mut_view_ok = default_engine_create_glwe_ciphertext_mut_view_from_u32(
      default_engine, accumulator, accumulator_size, poly_size, &accumulator_as_mut_view);
  assert(accumulator_as_mut_view_ok == 0);

  int trivial_encrypt_ok =
      default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_view_buffers(
          default_engine, accumulator_as_mut_view, expanded_tabulated_function_array, poly_size);
  assert(trivial_encrypt_ok == 0);

  // We perform the bootstrap
  int result_ok = fft_engine_lwe_ciphertext_discarding_bootstrap_u32_view_buffers(
      fft_engine, deser_fbsk, output_ct_as_mut_view, input_ct_as_view, accumulator_as_view);
  assert(result_ok == 0);

  uint32_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u32_view_buffers(
      default_engine, output_lwe_sk, output_ct_as_view, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Expected: %f, Obtained: %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.01);

  // We deallocate the objects
  destroy_lwe_secret_key_u32(input_lwe_sk);
  destroy_lwe_secret_key_u32(output_lwe_sk);
  destroy_glwe_secret_key_u32(output_glwe_sk);
  destroy_lwe_bootstrap_key_u32(bsk);
  destroy_lwe_bootstrap_key_u32(deser_bsk);
  destroy_lwe_seeded_bootstrap_key_u32(seeded_bsk);
  destroy_lwe_ciphertext_view_u32(input_ct_as_view);
  destroy_lwe_ciphertext_mut_view_u32(input_ct_as_mut_view);
  destroy_lwe_ciphertext_view_u32(output_ct_as_view);
  destroy_lwe_ciphertext_mut_view_u32(output_ct_as_mut_view);
  destroy_glwe_ciphertext_view_u32(accumulator_as_view);
  destroy_glwe_ciphertext_mut_view_u32(accumulator_as_mut_view);
  destroy_fft_fourier_lwe_bootstrap_key_u32(fbsk);
  destroy_fft_fourier_lwe_bootstrap_key_u32(deser_fbsk);
  destroy_fft_serialization_engine(fft_serialization_engine);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_serialization_engine(default_serialization_engine);
  destroy_default_engine(default_engine);
  destroy_fft_engine(fft_engine);
  destroy_seeder_builder(builder);
  destroy_buffer(&bsk_buffer);
  destroy_buffer(&seeded_bsk_buffer);
  destroy_buffer(&fbsk_buffer);
  free(tabulated_function_array);
  free(expanded_tabulated_function_array);
  free(accumulator);
  free(input_ct_buffer);
  free(output_ct_buffer);
}

void bootstrap_unchecked_view_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine_unchecked(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine_unchecked(&fft_engine);
  assert(fft_engine_ok == 0);

  FftSerializationEngine *fft_serialization_engine = NULL;

  int fft_serialization_engine_ok = new_fft_serialization_engine(&fft_serialization_engine);
  assert(fft_serialization_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey32 *input_lwe_sk = NULL;
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey32 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey32 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u32(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweSeededBootstrapKey32 *seeded_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_generate_new_lwe_seeded_bootstrap_key_unchecked_u32(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &seeded_bsk);
  assert(seeded_bsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer seeded_bsk_buffer = {.pointer = NULL, .length = 0};
  int seeded_bsk_ser_ok =
      default_serialization_engine_serialize_lwe_seeded_bootstrap_key_unchecked_u32(
          default_serialization_engine, seeded_bsk, &seeded_bsk_buffer);
  assert(seeded_bsk_ser_ok == 0);

  BufferView seeded_buffer_view = {.pointer = seeded_bsk_buffer.pointer,
                                   .length = seeded_bsk_buffer.length};
  LweSeededBootstrapKey32 *deser_seeded_bsk = NULL;
  int seeded_bsk_deser_ok =
      default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_unchecked_u32(
          default_serialization_engine, seeded_buffer_view, &deser_seeded_bsk);
  assert(seeded_bsk_deser_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_engine_transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked_u32(
      default_engine, &deser_seeded_bsk, &bsk);
  assert(bsk_ok == 0);

  Buffer bsk_buffer = {.pointer = NULL, .length = 0};
  int bsk_ser_ok = default_serialization_engine_serialize_lwe_bootstrap_key_unchecked_u32(
      default_serialization_engine, bsk, &bsk_buffer);
  assert(bsk_ser_ok == 0);

  BufferView bsk_deser_buffer_view = {.pointer = bsk_buffer.pointer, .length = bsk_buffer.length};
  LweBootstrapKey32 *deser_bsk = NULL;
  int bsk_deser_ok = default_serialization_engine_deserialize_lwe_bootstrap_key_unchecked_u32(
      default_serialization_engine, bsk_deser_buffer_view, &deser_bsk);
  assert(bsk_deser_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_unchecked_u32(
      fft_engine, deser_bsk, &fbsk);
  assert(fbsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer fbsk_buffer = {.pointer = NULL, .length = 0};
  int fbsk_ser_ok = fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_unchecked_u32(
      fft_serialization_engine, fbsk, &fbsk_buffer);
  assert(fbsk_ser_ok == 0);

  BufferView fbsk_buffer_view = {.pointer = fbsk_buffer.pointer, .length = fbsk_buffer.length};
  FftFourierLweBootstrapKey32 *deser_fbsk = NULL;
  int fbsk_deser_ok =
      fft_serialization_engine_deserialize_fft_fourier_lwe_bootstrap_key_unchecked_u32(
          fft_serialization_engine, fbsk_buffer_view, &deser_fbsk);
  assert(fbsk_deser_ok == 0);

  // We generate the ciphertexts
  uint32_t *input_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (input_lwe_dimension + 1));
  uint32_t *output_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (output_lwe_dimension + 1));
  uint32_t plaintext = ((uint32_t)4) << SHIFT;

  // Here we alias the same memory regions as immutable and mutable to be able to pass it to rust
  // as writable when needed and as read-only when needed
  LweCiphertextView32 *input_ct_as_view = NULL;
  int input_ct_ok = default_engine_create_lwe_ciphertext_view_from_unchecked_u32(
      default_engine, input_ct_buffer, input_lwe_dimension + 1, &input_ct_as_view);
  assert(input_ct_ok == 0);

  LweCiphertextMutView32 *input_ct_as_mut_view = NULL;
  int input_ct_as_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_unchecked_u32(
      default_engine, input_ct_buffer, input_lwe_dimension + 1, &input_ct_as_mut_view);
  assert(input_ct_as_mut_view_ok == 0);

  LweCiphertextView32 *output_ct_as_view = NULL;
  int output_ct_as_view_ok = default_engine_create_lwe_ciphertext_view_from_unchecked_u32(
      default_engine, output_ct_buffer, output_lwe_dimension + 1, &output_ct_as_view);
  assert(output_ct_as_view_ok == 0);

  LweCiphertextMutView32 *output_ct_as_mut_view = NULL;
  int output_ct_ok = default_engine_create_lwe_ciphertext_mut_view_from_unchecked_u32(
      default_engine, output_ct_buffer, output_lwe_dimension + 1, &output_ct_as_mut_view);
  assert(output_ct_ok == 0);

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u32_view_buffers(
      default_engine, input_lwe_sk, input_ct_as_mut_view, plaintext, encryption_variance);
  assert(encrypt_ok == 0);

  int tabulation_length = 1 << MESSAGE_BITS;

  size_t accumulator_size = poly_size * (glwe_dimension + 1);

  uint32_t *accumulator = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * accumulator_size);

  uint32_t *tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * tabulation_length);
  for (int i = 0; i < tabulation_length; i++) {
    tabulated_function_array[i] = (uint32_t)i;
  }

  uint32_t *expanded_tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * poly_size);

  encode_and_expand_lut(expanded_tabulated_function_array, poly_size, MESSAGE_BITS,
                        tabulated_function_array, tabulation_length);

  GlweCiphertextView32 *accumulator_as_view = NULL;
  int accumulator_as_view_ok = default_engine_create_glwe_ciphertext_view_from_unchecked_u32(
      default_engine, accumulator, accumulator_size, poly_size, &accumulator_as_view);
  assert(accumulator_as_view_ok == 0);

  GlweCiphertextMutView32 *accumulator_as_mut_view = NULL;
  int accumulator_as_mut_view_ok =
      default_engine_create_glwe_ciphertext_mut_view_from_unchecked_u32(
          default_engine, accumulator, accumulator_size, poly_size, &accumulator_as_mut_view);
  assert(accumulator_as_mut_view_ok == 0);

  int trivial_encrypt_ok =
      default_engine_discard_trivially_encrypt_glwe_ciphertext_unchecked_u32_view_buffers(
          default_engine, accumulator_as_mut_view, expanded_tabulated_function_array, poly_size);
  assert(trivial_encrypt_ok == 0);

  // We perform the bootstrap
  int result_ok = fft_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u32_view_buffers(
      fft_engine, deser_fbsk, output_ct_as_mut_view, input_ct_as_view, accumulator_as_view);
  assert(result_ok == 0);

  uint32_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_unchecked_u32_view_buffers(
      default_engine, output_lwe_sk, output_ct_as_view, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Expected: %f, Obtained: %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.01);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u32(input_lwe_sk);
  destroy_lwe_secret_key_unchecked_u32(output_lwe_sk);
  destroy_glwe_secret_key_unchecked_u32(output_glwe_sk);
  destroy_lwe_bootstrap_key_unchecked_u32(bsk);
  destroy_lwe_bootstrap_key_unchecked_u32(deser_bsk);
  destroy_lwe_seeded_bootstrap_key_unchecked_u32(seeded_bsk);
  destroy_lwe_ciphertext_view_unchecked_u32(input_ct_as_view);
  destroy_lwe_ciphertext_mut_view_unchecked_u32(input_ct_as_mut_view);
  destroy_lwe_ciphertext_view_unchecked_u32(output_ct_as_view);
  destroy_lwe_ciphertext_mut_view_unchecked_u32(output_ct_as_mut_view);
  destroy_glwe_ciphertext_view_unchecked_u32(accumulator_as_view);
  destroy_glwe_ciphertext_mut_view_unchecked_u32(accumulator_as_mut_view);
  destroy_fft_fourier_lwe_bootstrap_key_unchecked_u32(fbsk);
  destroy_fft_fourier_lwe_bootstrap_key_unchecked_u32(deser_fbsk);
  destroy_fft_serialization_engine_unchecked(fft_serialization_engine);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_serialization_engine_unchecked(default_serialization_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fft_engine_unchecked(fft_engine);
  destroy_seeder_builder_unchecked(builder);
  destroy_buffer_unchecked(&bsk_buffer);
  destroy_buffer_unchecked(&seeded_bsk_buffer);
  destroy_buffer_unchecked(&fbsk_buffer);
  free(tabulated_function_array);
  free(expanded_tabulated_function_array);
  free(accumulator);
  free(input_ct_buffer);
  free(output_ct_buffer);
}

void bootstrap_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine(&fft_engine);
  assert(fft_engine_ok == 0);

  FftSerializationEngine *fft_serialization_engine = NULL;

  int fft_serialization_engine_ok = new_fft_serialization_engine(&fft_serialization_engine);
  assert(fft_serialization_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey32 *input_lwe_sk = NULL;
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_u32(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey32 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_u32(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey32 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_u32(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweSeededBootstrapKey32 *seeded_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_generate_new_lwe_seeded_bootstrap_key_u32(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &seeded_bsk);
  assert(seeded_bsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer seeded_bsk_buffer = {.pointer = NULL, .length = 0};
  int seeded_bsk_ser_ok = default_serialization_engine_serialize_lwe_seeded_bootstrap_key_u32(
      default_serialization_engine, seeded_bsk, &seeded_bsk_buffer);
  assert(seeded_bsk_ser_ok == 0);

  BufferView seeded_buffer_view = {.pointer = seeded_bsk_buffer.pointer,
                                   .length = seeded_bsk_buffer.length};
  LweSeededBootstrapKey32 *deser_seeded_bsk = NULL;
  int seeded_bsk_deser_ok = default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_u32(
      default_serialization_engine, seeded_buffer_view, &deser_seeded_bsk);
  assert(seeded_bsk_deser_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_engine_transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_u32(
      default_engine, &deser_seeded_bsk, &bsk);
  assert(bsk_ok == 0);

  Buffer bsk_buffer = {.pointer = NULL, .length = 0};
  int bsk_ser_ok = default_serialization_engine_serialize_lwe_bootstrap_key_u32(
      default_serialization_engine, bsk, &bsk_buffer);
  assert(bsk_ser_ok == 0);

  BufferView bsk_deser_buffer_view = {.pointer = bsk_buffer.pointer, .length = bsk_buffer.length};
  LweBootstrapKey32 *deser_bsk = NULL;
  int bsk_deser_ok = default_serialization_engine_deserialize_lwe_bootstrap_key_u32(
      default_serialization_engine, bsk_deser_buffer_view, &deser_bsk);
  assert(bsk_deser_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_u32(
      fft_engine, deser_bsk, &fbsk);
  assert(fbsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer fbsk_buffer = {.pointer = NULL, .length = 0};
  int fbsk_ser_ok = fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_u32(
      fft_serialization_engine, fbsk, &fbsk_buffer);
  assert(fbsk_ser_ok == 0);

  BufferView fbsk_buffer_view = {.pointer = fbsk_buffer.pointer, .length = fbsk_buffer.length};
  FftFourierLweBootstrapKey32 *deser_fbsk = NULL;
  int fbsk_deser_ok = fft_serialization_engine_deserialize_fft_fourier_lwe_bootstrap_key_u32(
      fft_serialization_engine, fbsk_buffer_view, &deser_fbsk);
  assert(fbsk_deser_ok == 0);

  // We generate the ciphertexts
  uint32_t *input_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (input_lwe_dimension + 1));
  uint32_t *output_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (output_lwe_dimension + 1));
  uint32_t plaintext = ((uint32_t)4) << SHIFT;

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u32_raw_ptr_buffers(
      default_engine, input_lwe_sk, input_ct_buffer, plaintext, encryption_variance);
  assert(encrypt_ok == 0);

  int tabulation_length = 1 << MESSAGE_BITS;

  size_t accumulator_size = poly_size * (glwe_dimension + 1);

  uint32_t *accumulator = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * accumulator_size);

  uint32_t *tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * tabulation_length);
  for (int i = 0; i < tabulation_length; i++) {
    tabulated_function_array[i] = (uint32_t)i;
  }

  uint32_t *expanded_tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * poly_size);

  encode_and_expand_lut(expanded_tabulated_function_array, poly_size, MESSAGE_BITS,
                        tabulated_function_array, tabulation_length);

  int trivial_encrypt_ok =
      default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_raw_ptr_buffers(
          default_engine, accumulator, accumulator_size, expanded_tabulated_function_array,
          poly_size);
  assert(trivial_encrypt_ok == 0);

  // We perform the bootstrap
  int result_ok = fft_engine_lwe_ciphertext_discarding_bootstrap_u32_raw_ptr_buffers(
      fft_engine, default_engine, deser_fbsk, output_ct_buffer, input_ct_buffer, accumulator);
  assert(result_ok == 0);

  uint32_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u32_raw_ptr_buffers(
      default_engine, output_lwe_sk, output_ct_buffer, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Expected: %f, Obtained: %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.01);

  // We deallocate the objects
  destroy_lwe_secret_key_u32(input_lwe_sk);
  destroy_lwe_secret_key_u32(output_lwe_sk);
  destroy_glwe_secret_key_u32(output_glwe_sk);
  destroy_lwe_bootstrap_key_u32(bsk);
  destroy_lwe_bootstrap_key_u32(deser_bsk);
  destroy_lwe_seeded_bootstrap_key_u32(seeded_bsk);
  destroy_fft_fourier_lwe_bootstrap_key_u32(fbsk);
  destroy_fft_fourier_lwe_bootstrap_key_u32(deser_fbsk);
  destroy_fft_serialization_engine(fft_serialization_engine);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_serialization_engine(default_serialization_engine);
  destroy_default_engine(default_engine);
  destroy_fft_engine(fft_engine);
  destroy_seeder_builder(builder);
  destroy_buffer(&bsk_buffer);
  destroy_buffer(&seeded_bsk_buffer);
  destroy_buffer(&fbsk_buffer);
  free(tabulated_function_array);
  free(expanded_tabulated_function_array);
  free(accumulator);
  free(input_ct_buffer);
  free(output_ct_buffer);
}

void bootstrap_unchecked_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine_unchecked(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  FftEngine *fft_engine = NULL;

  int fft_engine_ok = new_fft_engine_unchecked(&fft_engine);
  assert(fft_engine_ok == 0);

  FftSerializationEngine *fft_serialization_engine = NULL;

  int fft_serialization_engine_ok = new_fft_serialization_engine(&fft_serialization_engine);
  assert(fft_serialization_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
  size_t input_lwe_dimension = 2;
  size_t poly_size = 1024;
  size_t level = 3;
  size_t base_log = 5;
  size_t output_lwe_dimension = glwe_dimension * poly_size;

  // We generate the keys
  LweSecretKey32 *input_lwe_sk = NULL;
  int lwe_in_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(
      default_engine, input_lwe_dimension, &input_lwe_sk);
  assert(lwe_in_key_ok == 0);

  LweSecretKey32 *output_lwe_sk = NULL;
  int lwe_out_key_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(
      default_engine, output_lwe_dimension, &output_lwe_sk);
  assert(lwe_out_key_ok == 0);

  GlweSecretKey32 *output_glwe_sk = NULL;

  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u32(
      default_engine, output_lwe_sk, poly_size, &output_glwe_sk);
  assert(clone_transform_ok == 0);

  LweSeededBootstrapKey32 *seeded_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_generate_new_lwe_seeded_bootstrap_key_unchecked_u32(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &seeded_bsk);
  assert(seeded_bsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer seeded_bsk_buffer = {.pointer = NULL, .length = 0};
  int seeded_bsk_ser_ok =
      default_serialization_engine_serialize_lwe_seeded_bootstrap_key_unchecked_u32(
          default_serialization_engine, seeded_bsk, &seeded_bsk_buffer);
  assert(seeded_bsk_ser_ok == 0);

  BufferView seeded_buffer_view = {.pointer = seeded_bsk_buffer.pointer,
                                   .length = seeded_bsk_buffer.length};
  LweSeededBootstrapKey32 *deser_seeded_bsk = NULL;
  int seeded_bsk_deser_ok =
      default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_unchecked_u32(
          default_serialization_engine, seeded_buffer_view, &deser_seeded_bsk);
  assert(seeded_bsk_deser_ok == 0);

  LweBootstrapKey32 *bsk = NULL;
  int bsk_ok = default_engine_transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_unchecked_u32(
      default_engine, &deser_seeded_bsk, &bsk);
  assert(bsk_ok == 0);

  Buffer bsk_buffer = {.pointer = NULL, .length = 0};
  int bsk_ser_ok = default_serialization_engine_serialize_lwe_bootstrap_key_unchecked_u32(
      default_serialization_engine, bsk, &bsk_buffer);
  assert(bsk_ser_ok == 0);

  BufferView bsk_deser_buffer_view = {.pointer = bsk_buffer.pointer, .length = bsk_buffer.length};
  LweBootstrapKey32 *deser_bsk = NULL;
  int bsk_deser_ok = default_serialization_engine_deserialize_lwe_bootstrap_key_unchecked_u32(
      default_serialization_engine, bsk_deser_buffer_view, &deser_bsk);
  assert(bsk_deser_ok == 0);

  FftFourierLweBootstrapKey32 *fbsk = NULL;
  int fbsk_ok = fft_engine_convert_lwe_bootstrap_key_to_fft_fourier_lwe_bootstrap_key_unchecked_u32(
      fft_engine, deser_bsk, &fbsk);
  assert(fbsk_ok == 0);

  // Test BSK Serialization/Deserialization
  Buffer fbsk_buffer = {.pointer = NULL, .length = 0};
  int fbsk_ser_ok = fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_u32(
      fft_serialization_engine, fbsk, &fbsk_buffer);
  assert(fbsk_ser_ok == 0);

  BufferView fbsk_buffer_view = {.pointer = fbsk_buffer.pointer, .length = fbsk_buffer.length};
  FftFourierLweBootstrapKey32 *deser_fbsk = NULL;
  int fbsk_deser_ok =
      fft_serialization_engine_deserialize_fft_fourier_lwe_bootstrap_key_unchecked_u32(
          fft_serialization_engine, fbsk_buffer_view, &deser_fbsk);
  assert(fbsk_deser_ok == 0);

  // We generate the ciphertexts
  uint32_t *input_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (input_lwe_dimension + 1));
  uint32_t *output_ct_buffer =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (output_lwe_dimension + 1));
  uint32_t plaintext = ((uint32_t)4) << SHIFT;

  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u32_raw_ptr_buffers(
      default_engine, input_lwe_sk, input_ct_buffer, plaintext, encryption_variance);
  assert(encrypt_ok == 0);

  int tabulation_length = 1 << MESSAGE_BITS;

  size_t accumulator_size = poly_size * (glwe_dimension + 1);

  uint32_t *accumulator = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * accumulator_size);

  uint32_t *tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * tabulation_length);
  for (int i = 0; i < tabulation_length; i++) {
    tabulated_function_array[i] = (uint32_t)i;
  }

  uint32_t *expanded_tabulated_function_array =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * poly_size);

  encode_and_expand_lut(expanded_tabulated_function_array, poly_size, MESSAGE_BITS,
                        tabulated_function_array, tabulation_length);

  int trivial_encrypt_ok =
      default_engine_discard_trivially_encrypt_glwe_ciphertext_unchecked_u32_raw_ptr_buffers(
          default_engine, accumulator, accumulator_size, expanded_tabulated_function_array,
          poly_size);
  assert(trivial_encrypt_ok == 0);

  // We perform the bootstrap
  int result_ok = fft_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u32_raw_ptr_buffers(
      fft_engine, default_engine, deser_fbsk, output_ct_buffer, input_ct_buffer, accumulator);
  assert(result_ok == 0);

  uint32_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_unchecked_u32_raw_ptr_buffers(
      default_engine, output_lwe_sk, output_ct_buffer, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Expected: %f, Obtained: %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.01);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u32(input_lwe_sk);
  destroy_lwe_secret_key_unchecked_u32(output_lwe_sk);
  destroy_glwe_secret_key_unchecked_u32(output_glwe_sk);
  destroy_lwe_bootstrap_key_unchecked_u32(bsk);
  destroy_lwe_bootstrap_key_unchecked_u32(deser_bsk);
  destroy_lwe_seeded_bootstrap_key_unchecked_u32(seeded_bsk);
  destroy_fft_fourier_lwe_bootstrap_key_unchecked_u32(fbsk);
  destroy_fft_fourier_lwe_bootstrap_key_unchecked_u32(deser_fbsk);
  destroy_fft_serialization_engine_unchecked(fft_serialization_engine);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_serialization_engine_unchecked(default_serialization_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fft_engine_unchecked(fft_engine);
  destroy_seeder_builder_unchecked(builder);
  destroy_buffer_unchecked(&bsk_buffer);
  destroy_buffer_unchecked(&seeded_bsk_buffer);
  destroy_buffer_unchecked(&fbsk_buffer);
  free(tabulated_function_array);
  free(expanded_tabulated_function_array);
  free(accumulator);
  free(input_ct_buffer);
  free(output_ct_buffer);
}

int main(void) {
  bootstrap_view_buffers_test();
  bootstrap_unchecked_view_buffers_test();
  bootstrap_raw_ptr_buffers_test();
  bootstrap_unchecked_raw_ptr_buffers_test();
  return EXIT_SUCCESS;
}
