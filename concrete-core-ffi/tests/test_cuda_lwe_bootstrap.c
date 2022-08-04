#include "concrete-core-ffi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

// This helper function expands the input LUT into output, duplicating values as needed to fill
// mega cases, taking care of the encoding and the half mega case shift in the process as well.
// All sizes should be powers of 2.
void encode_and_expand_lut(uint64_t *output, size_t output_size, size_t out_MESSAGE_BITS,
                           const uint64_t *lut, size_t lut_size) {
  assert((output_size % lut_size) == 0);

  size_t mega_case_size = output_size / lut_size;

  assert((mega_case_size % 2) == 0);

  for (size_t idx = 0; idx < mega_case_size / 2; ++idx) {
    output[idx] = lut[0] << (64 - out_MESSAGE_BITS - 1);
  }

  for (size_t idx = (lut_size - 1) * mega_case_size + mega_case_size / 2; idx < output_size;
       ++idx) {
    output[idx] = -(lut[0] << (64 - out_MESSAGE_BITS - 1));
  }

  for (size_t lut_idx = 1; lut_idx < lut_size; ++lut_idx) {
    uint64_t lut_value = lut[lut_idx] << (64 - out_MESSAGE_BITS - 1);
    size_t start = mega_case_size * (lut_idx - 1) + mega_case_size / 2;
    for (size_t output_idx = start; output_idx < start + mega_case_size; ++output_idx) {
      output[output_idx] = lut_value;
    }
  }
}

void lowlat_bootstrap_view_buffers_test(void) {
  // We generate the random sources
  DefaultEngine *engine = NULL;
  CudaEngine *cuda_engine = NULL;
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &engine);
  assert(default_engine_ok == 0);

  int cuda_engine_ok = new_cuda_engine(builder, &cuda_engine);
  assert(cuda_engine_ok == 0);

  double pbs_variance = 0.00000000000001;
  double encryption_variance = 0.0000000001;
  size_t glwe_dimension = 1;
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

  LweSeededBootstrapKey64 *seeded_bsk = NULL;
  int seeded_bsk_ok = default_parallel_engine_create_lwe_seeded_bootstrap_key_u64(
      default_parallel_engine, input_lwe_sk, output_glwe_sk, base_log, level, pbs_variance,
      &seeded_bsk);
  assert(seeded_bsk_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_engine_transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_u64(
      default_engine, &deser_seeded_bsk, &bsk);
  assert(bsk_ok == 0);

  CudaFourierLweBootstrapKey64 *d_bsk = NULL;
  int d_bsk_ok = cuda_engine_convert_lwe_bootstrap_key_to_cuda_fourier_lwe_bootstrap_key_u64(
      cuda_engine, bsk, &d_bsk);
  assert(d_bsk_ok == 0);

  // We create the buffers
  uint64_t *input_ct_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
  uint64_t *output_ct_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
  uint64_t plaintext = {((uint64_t)1) << SHIFT};

  // Here we alias the same memory regions as immutable and mutable to be able to pass it to rust
  // as writable when needed and as read-only when needed
  LweCiphertextView64 *input_ct_as_view = NULL;
  int input_ct_ok = default_engine_create_lwe_ciphertext_view_u64(
      default_engine, input_ct_buffer, input_lwe_dimension + 1, &input_ct_as_view);
  assert(input_ct_ok == 0);

  LweCiphertextMutView64 *input_ct_as_mut_view = NULL;
  int input_ct_as_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_u64(
      default_engine, input_ct_buffer, input_lwe_dimension + 1, &input_ct_as_mut_view);
  assert(input_ct_as_mut_view_ok == 0);

  LweCiphertextView64 *output_ct_as_view = NULL;
  int output_ct_as_view_ok = default_engine_create_lwe_ciphertext_view_u64(
      default_engine, output_ct_buffer, output_lwe_dimension + 1, &output_ct_as_view);
  assert(output_ct_as_view_ok == 0);

  LweCiphertextMutView64 *output_ct_as_mut_view = NULL;
  int output_ct_ok = default_engine_create_lwe_ciphertext_mut_view_u64(
      default_engine, output_ct_buffer, output_lwe_dimension + 1, &output_ct_as_mut_view);
  assert(output_ct_ok == 0);

  // We encrypt the plaintext
  int enc_ct_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers(
          engine, sk, input_ct_as_mut_view, plaintext, variance);
  assert(enc_ct_ok == 0);

  int tabulation_length = 1 << MESSAGE_BITS;

  size_t accumulator_size = poly_size * (glwe_dimension + 1);

  uint64_t *accumulator = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * accumulator_size);

  uint64_t *tabulated_function_array =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * tabulation_length);
  for (int i = 0; i < tabulation_length; i++) {
    tabulated_function_array[i] = (uint64_t)i;
  }

  uint64_t *expanded_tabulated_function_array =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * poly_size);

  encode_and_expand_lut(expanded_tabulated_function_array, poly_size, MESSAGE_BITS,
                        tabulated_function_array, tabulation_length);

  GlweCiphertextView64 *accumulator_as_view = NULL;
  int accumulator_as_view_ok = default_engine_create_glwe_ciphertext_view_u64(
      default_engine, accumulator, accumulator_size, poly_size, &accumulator_as_view);
  assert(accumulator_as_view_ok == 0);

  GlweCiphertextMutView64 *accumulator_as_mut_view = NULL;
  int accumulator_as_mut_view_ok = default_engine_create_glwe_ciphertext_mut_view_u64(
      default_engine, accumulator, accumulator_size, poly_size, &accumulator_as_mut_view);
  assert(accumulator_as_mut_view_ok == 0);

  int trivial_encrypt_ok =
      default_engine_discard_trivially_encrypt_glwe_ciphertext_u64_view_buffers(
          default_engine, accumulator_as_mut_view, expanded_tabulated_function_array, poly_size);
  assert(trivial_encrypt_ok == 0);

  // We convert to the device
  CudaLweCiphertext64 *d_input_ct = NULL;
  int convert_ok = cuda_engine_convert_lwe_ciphertext_view_to_cuda_lwe_ciphertext_u64(
          cuda_engine, input_ct_as_view, d_input_ct);
  CudaGlweCiphertext64 *d_accumulator = NULL;
  int convert_ok = cuda_engine_convert_glwe_ciphertext_mut_view_to_cuda_glwe_ciphertext_u64(
          cuda_engine, accumulator_as_mut_view, d_accumulator);
   // We do this only to create the cuda object
  CudaLweCiphertext64 *d_output_ct = NULL;
  int convert_ok = cuda_engine_convert_lwe_ciphertext_view_to_cuda_lwe_ciphertext_u64(
          cuda_engine, output_ct_as_view, d_output_ct);

    // We perform the bootstrap
  int result_ok = cuda_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers(
      cuda_engine, d_bsk, d_output_ct, d_input_ct, d_accumulator);
  assert(result_ok == 0);

  // We decrypt the plaintext
  int convert_ok = cuda_engine_convert_cuda_lwe_ciphertext_to_lwe_ciphertext_view_u64(
          cuda_engine, d_output_ct, output_ct_as_view);

  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u64_view_buffers(
      engine, sk, output_ct_as_view, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  printf("Comparing output. Expected %f, Obtained %f\n", plaintext, output);
  double abs_diff = abs(output - plaintext);
  double rel_error = abs_diff / fmax(plaintext, output);
  assert(rel_error < 0.002);

  // We deallocate the objects
  default_engine_destroy_lwe_secret_key_u64(default_engine, input_lwe_sk);
  default_engine_destroy_lwe_secret_key_u64(default_engine, output_lwe_sk);
  default_engine_destroy_glwe_secret_key_u64(default_engine, output_glwe_sk);
  default_engine_destroy_lwe_bootstrap_key_u64(default_engine, bsk);
  default_engine_destroy_lwe_ciphertext_view_u64(engine, input_ct_as_view);
  default_engine_destroy_lwe_ciphertext_view_u64(engine, output_ct_as_view);
  default_engine_destroy_glwe_ciphertext_view_u64(default_engine, accumulator_as_view);
  default_engine_destroy_glwe_ciphertext_view_u64(default_engine, accumulator_as_mut_view);
  cuda_engine_destroy_cuda_lwe_ciphertext_u64(engine, d_input_ct);
  cuda_engine_destroy_cuda_lwe_ciphertext_u64(engine, d_output_ct);
  cuda_engine_destroy_cuda_lwe_ciphertext_u64(engine, d_accumulator);
  destroy_default_engine(engine);
  destroy_cuda_engine(cuda_engine);
  destroy_seeder_builder(builder);
  free(tabulated_function_array);
  free(expanded_tabulated_function_array);
  free(accumulator);
  free(input_ct_buffer);
  free(output_ct_buffer);
}
int main(void) {
    lowlat_bootstrap_view_buffers_test();
  return EXIT_SUCCESS;
}
