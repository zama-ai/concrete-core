#include "concrete-core-ffi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void encrypt_lwe_vector_decrypt_view_buffers_test(void) {
  // We generate all the needed tools
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &engine);
  assert(default_engine_ok == 0);
  size_t lwe_dimension = 10;
  size_t lwe_count = 10;
  LweSecretKey32 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_u32(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  uint32_t *input_ct_vector_buffer = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_dimension + 1)
  * lwe_count);
  uint32_t *output_ct_vector_buffer = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_dimension + 
  1) * lwe_count);

  LweCiphertextVectorView32 *input_ct_vector_as_view = NULL;
  int input_ct_vector_as_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_u32(
      engine, input_ct_vector_buffer, lwe_dimension + 1, lwe_count, &input_ct_vector_as_view);
  assert(input_ct_vector_as_view_ok == 0);

  LweCiphertextVectorMutView32 *input_ct_vector_as_mut_view = NULL;
  int input_ct_vector_as_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_u32(
      engine, input_ct_vector_buffer, lwe_dimension + 1, lwe_count, &input_ct_vector_as_mut_view);
  assert(input_ct_vector_as_mut_view_ok == 0);

  LweCiphertextVectorView32 *output_ct_vector_as_view = NULL;
  int output_ct_vector_as_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_u32(
      engine, output_ct_vector_buffer, lwe_dimension + 1, lwe_count, &output_ct_vector_as_view);
  assert(output_ct_vector_as_view_ok == 0);

  uint32_t *plaintext_vector =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  for (uint i = 0; i < lwe_count; i++) {
    plaintext_vector[i] = ((uint32_t) 1) << SHIFT;
  }
  double variance = 0.000;

  // We encrypt the plaintext
  int enc_input_ct_vector_ok = default_engine_discard_encrypt_lwe_ciphertext_vector_u32_view_buffers(
      engine, sk, input_ct_vector_as_mut_view, plaintext_vector, variance, lwe_count);
  assert(enc_input_ct_vector_ok == 0);

  // We decrypt the plaintext
  uint32_t *output = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u32_view_buffers(
      engine, sk, input_ct_vector_as_view, output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = ((double)plaintext_vector[0]) / pow(2, SHIFT);
  double obtained = (double)output[0] / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_u32(sk);
  destroy_lwe_ciphertext_vector_view_u32(input_ct_vector_as_view);
  destroy_lwe_ciphertext_vector_mut_view_u32(input_ct_vector_as_mut_view);
  destroy_lwe_ciphertext_vector_view_u32(output_ct_vector_as_view);

  destroy_default_engine(engine);
  destroy_seeder_builder(builder);
  free(input_ct_vector_buffer);
  free(output_ct_vector_buffer);
  free(output);
}

void encrypt_lwe_vector_decrypt_unchecked_view_buffers_test(void) {
  // We generate all the needed tools
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &engine);
  assert(default_engine_ok == 0);
  size_t lwe_dimension = 10;
  size_t lwe_count = 10;
  LweSecretKey32 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  uint32_t *input_ct_vector_buffer = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_dimension + 1)
                                                                  * lwe_count);
  uint32_t *output_ct_vector_buffer = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * (lwe_dimension +
                                                                                       1) * lwe_count);

  LweCiphertextVectorView32 *input_ct_vector_as_view = NULL;
  int input_ct_vector_as_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_unchecked_u32(
      engine, input_ct_vector_buffer, lwe_dimension + 1, lwe_count, &input_ct_vector_as_view);
  assert(input_ct_vector_as_view_ok == 0);

  LweCiphertextVectorMutView32 *input_ct_vector_as_mut_view = NULL;
  int input_ct_vector_as_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_unchecked_u32(
      engine, input_ct_vector_buffer, lwe_dimension + 1, lwe_count, &input_ct_vector_as_mut_view);
  assert(input_ct_vector_as_mut_view_ok == 0);

  LweCiphertextVectorView32 *output_ct_vector_as_view = NULL;
  int output_ct_vector_as_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_unchecked_u32(
      engine, output_ct_vector_buffer, lwe_dimension + 1, lwe_count, &output_ct_vector_as_view);
  assert(output_ct_vector_as_view_ok == 0);

  uint32_t *plaintext_vector =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  for (uint i = 0; i < lwe_count; i++) {
    plaintext_vector[i] = ((uint32_t) 1) << SHIFT;
  }
  double variance = 0.000;

  // We encrypt the plaintext
  int enc_input_ct_vector_ok = 
      default_engine_discard_encrypt_lwe_ciphertext_vector_unchecked_u32_view_buffers(
      engine, sk, input_ct_vector_as_mut_view, plaintext_vector, variance, lwe_count);
  assert(enc_input_ct_vector_ok == 0);

  // We decrypt the plaintext
  uint32_t *output = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u32_view_buffers(
      engine, sk, input_ct_vector_as_view, output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = ((double)plaintext_vector[0]) / pow(2, SHIFT);
  double obtained = (double)output[0] / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u32(sk);
  destroy_lwe_ciphertext_vector_view_unchecked_u32(input_ct_vector_as_view);
  destroy_lwe_ciphertext_vector_mut_view_unchecked_u32(input_ct_vector_as_mut_view);
  destroy_lwe_ciphertext_vector_view_unchecked_u32(output_ct_vector_as_view);

  destroy_default_engine_unchecked(engine);
  destroy_seeder_builder_unchecked(builder);
  free(input_ct_vector_buffer);
  free(output_ct_vector_buffer);
  free(output);
}

void encrypt_lwe_vector_decrypt_raw_ptr_buffers_test(void) {
  // We generate all the needed tools
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &engine);
  assert(default_engine_ok == 0);
  size_t lwe_dimension = 10;
  size_t lwe_count = 10;
  LweSecretKey32 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_u32(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  uint32_t *input_ct_vector_buffer = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t)
                                                                  * (lwe_dimension + 1) * lwe_count);
  uint32_t *plaintext_vector =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  for (uint i = 0; i < lwe_count; i++) {
    plaintext_vector[i] = ((uint32_t) 1) << SHIFT;
  }
  double variance = 0.000;

  // We encrypt the plaintext
  int enc_input_ct_vector_ok = default_engine_discard_encrypt_lwe_ciphertext_vector_u32_raw_ptr_buffers(
      engine, sk, input_ct_vector_buffer, plaintext_vector, variance, lwe_count);
  assert(enc_input_ct_vector_ok == 0);

  // We decrypt the plaintext
  uint32_t *output = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u32_raw_ptr_buffers(
      engine, sk, input_ct_vector_buffer, output, lwe_count);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = ((double)plaintext_vector[0]) / pow(2, SHIFT);
  double obtained = (double)output[0] / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_u32(sk);
  destroy_default_engine(engine);
  destroy_seeder_builder(builder);
  free(input_ct_vector_buffer);
  free(output);
}

void encrypt_lwe_vector_decrypt_unchecked_raw_ptr_buffers_test(void) {
  // We generate all the needed tools
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &engine);
  assert(default_engine_ok == 0);
  size_t lwe_dimension = 10;
  size_t lwe_count = 10;
  LweSecretKey32 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u32(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  uint32_t *input_ct_vector_buffer = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * 
  (lwe_dimension + 1) * lwe_count);

  uint32_t *plaintext_vector =
      aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  for (uint i = 0; i < lwe_count; i++) {
    plaintext_vector[i] = ((uint32_t) 1) << SHIFT;
  }
  double variance = 0.000;

  // We encrypt the plaintext
  int enc_input_ct_vector_ok = default_engine_discard_encrypt_lwe_ciphertext_vector_unchecked_u32_raw_ptr_buffers(
      engine, sk, input_ct_vector_buffer, plaintext_vector, variance, lwe_count);
  assert(enc_input_ct_vector_ok == 0);

  // We decrypt the plaintext
  uint32_t *output = aligned_alloc(U32_ALIGNMENT, sizeof(uint32_t) * lwe_count);
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u32_raw_ptr_buffers(
      engine, sk, input_ct_vector_buffer, output, lwe_count);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = ((double)plaintext_vector[0]) / pow(2, SHIFT);
  double obtained = (double)output[0] / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = fabs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u32(sk);
  destroy_default_engine_unchecked(engine);
  destroy_seeder_builder_unchecked(builder);
  free(input_ct_vector_buffer);
  free(output);
}

int main(void) {
  encrypt_lwe_vector_decrypt_view_buffers_test();
  encrypt_lwe_vector_decrypt_unchecked_view_buffers_test();
  encrypt_lwe_vector_decrypt_raw_ptr_buffers_test();
  encrypt_lwe_vector_decrypt_unchecked_raw_ptr_buffers_test();
  return EXIT_SUCCESS;
}
