#include "concrete-core-ffi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void convert_view_buffers_test(void) {
  // We generate the random sources
  DefaultEngine *engine = NULL;
  CudaEngine *cuda_engine = NULL;
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &engine);
  assert(default_engine_ok == 0);

  int cuda_engine_ok = new_cuda_engine(builder, &cuda_engine);
  assert(cuda_engine_ok == 0);

  double variance = 0.000000001;

  // We generate the secret key
  size_t lwe_dimension = 10;
  LweSecretKey64 *sk = NULL;
  int sk_ok = default_engine_create_lwe_secret_key_u64(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  // We create the buffers
  uint64_t *input_ct_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
  uint64_t *output_ct_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));
  uint64_t plaintext = {((uint64_t)1) << SHIFT};

  // We create the ciphertexts as views
  LweCiphertextView64 *input_ct_as_view = NULL;
  int input_ct_as_view_ok = default_engine_create_lwe_ciphertext_view_u64(
          engine, input_ct_buffer, lwe_dimension + 1, &input_ct_as_view);
  assert(input_ct_as_view_ok == 0);

  LweCiphertextView64 *output_ct_as_view = NULL;
  int output_ct_as_view_ok = default_engine_create_lwe_ciphertext_view_u64(
          engine, output_ct_buffer, lwe_dimension + 1, &output_ct_as_view);
  assert(output_ct_as_view_ok == 0);

  // We encrypt the plaintext
  int enc_ct_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers(
          engine, sk, input_ct_as_mut_view, plaintext, variance);
  assert(enc_ct_ok == 0);

  // We convert backward and forward
  CudaLweCiphertext64 *d_input_ct = NULL;
  int convert_ok = cuda_engine_convert_lwe_ciphertext_view_to_cuda_lwe_ciphertext_u64(
          cuda_engine, input_ct_as_view, d_input_ct);
  int convert_ok = cuda_engine_convert_cuda_lwe_ciphertext_to_lwe_ciphertext_view_u64(
          cuda_engine, d_input_ct, output_ct_as_view);

  // We decrypt the plaintext
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
  default_engine_destroy_lwe_secret_key_u64(engine, sk);
  default_engine_destroy_lwe_ciphertext_view_u64(engine, input_ct_as_view);
  default_engine_destroy_lwe_ciphertext_view_u64(engine, output_ct_as_view);
  cuda_engine_destroy_cuda_lwe_ciphertext_u64(engine, d_input_ct);
  destroy_default_engine(engine);
  destroy_cuda_engine(cuda_engine);
  destroy_seeder_builder(builder);
  free(input_ct_buffer);
  free(output_ct_buffer);
}
int main(void) {
    convert_view_buffers_test();
  return EXIT_SUCCESS;
}
