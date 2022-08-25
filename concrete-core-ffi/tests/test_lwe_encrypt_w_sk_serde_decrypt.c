#include "concrete-core-ffi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void encrypt_decrypt_view_buffers_test(void) {
  // We generate the random sources
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &engine);
  assert(default_engine_ok == 0);
  assert(engine != NULL);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  double variance = 0.000000001;

  // We generate the key
  uint64_t lwe_dimension = 10;
  LweSecretKey64 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_u64(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  // We generate the texts
  uint64_t *ciphertext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));

  LweCiphertextMutView64 *ciphertext_as_mut_view = NULL;
  int ct_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_u64(
      engine, ciphertext_buffer, lwe_dimension + 1, &ciphertext_as_mut_view);
  assert(ct_mut_view_ok == 0);

  LweCiphertextView64 *ciphertext_as_view = NULL;
  int ct_view_ok = default_engine_create_lwe_ciphertext_view_from_u64(
      engine, ciphertext_buffer, lwe_dimension + 1, &ciphertext_as_view);
  assert(ct_view_ok == 0);

  uint64_t plaintext = ((uint64_t)10) << SHIFT;

  // We encrypt the plaintext
  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers(
      engine, sk, ciphertext_as_mut_view, plaintext, variance);
  assert(encrypt_ok == 0);

  // Test SK Serialization/Deserialization
  Buffer sk_buffer = {.pointer = NULL, .length = 0};
  int sk_ser_ok = default_serialization_engine_serialize_lwe_secret_key_u64(
      default_serialization_engine, sk, &sk_buffer);
  assert(sk_ser_ok == 0);

  BufferView sk_buffer_view = {.pointer = sk_buffer.pointer, .length = sk_buffer.length};
  LweSecretKey64 *deser_sk = NULL;
  int sk_deser_ok = default_serialization_engine_deserialize_lwe_secret_key_u64(
      default_serialization_engine, sk_buffer_view, &deser_sk);
  assert(sk_deser_ok == 0);

  // We decrypt the plaintext
  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u64_view_buffers(
      engine, deser_sk, ciphertext_as_view, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = abs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_u64(sk);
  destroy_lwe_secret_key_u64(deser_sk);
  destroy_lwe_ciphertext_view_u64(ciphertext_as_view);
  destroy_lwe_ciphertext_mut_view_u64(ciphertext_as_mut_view);
  destroy_seeder_builder(builder);
  destroy_default_serialization_engine(default_serialization_engine);
  destroy_default_engine(engine);
  destroy_buffer(&sk_buffer);
  free(ciphertext_buffer);
}

void encrypt_decrypt_unchecked_view_buffers_test(void) { // We generate the random sources
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &engine);
  assert(default_engine_ok == 0);
  assert(engine != NULL);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  double variance = 0.000000001;

  // We generate the key
  uint64_t lwe_dimension = 10;
  LweSecretKey64 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  // We generate the texts
  uint64_t *ciphertext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));

  LweCiphertextMutView64 *ciphertext_as_mut_view = NULL;
  int ct_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_unchecked_u64(
      engine, ciphertext_buffer, lwe_dimension + 1, &ciphertext_as_mut_view);
  assert(ct_mut_view_ok == 0);

  LweCiphertextView64 *ciphertext_as_view = NULL;
  int ct_view_ok = default_engine_create_lwe_ciphertext_view_from_unchecked_u64(
      engine, ciphertext_buffer, lwe_dimension + 1, &ciphertext_as_view);
  assert(ct_view_ok == 0);

  uint64_t plaintext = ((uint64_t)10) << SHIFT;

  // We encrypt the plaintext
  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_view_buffers(
      engine, sk, ciphertext_as_mut_view, plaintext, variance);
  assert(encrypt_ok == 0);

  // Test SK Serialization/Deserialization
  Buffer sk_buffer = {.pointer = NULL, .length = 0};
  int sk_ser_ok = default_serialization_engine_serialize_lwe_secret_key_u64(
      default_serialization_engine, sk, &sk_buffer);
  assert(sk_ser_ok == 0);

  BufferView sk_buffer_view = {.pointer = sk_buffer.pointer, .length = sk_buffer.length};
  LweSecretKey64 *deser_sk = NULL;
  int sk_deser_ok = default_serialization_engine_deserialize_lwe_secret_key_u64(
      default_serialization_engine, sk_buffer_view, &deser_sk);
  assert(sk_deser_ok == 0);

  // We decrypt the plaintext
  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_unchecked_u64_view_buffers(
      engine, deser_sk, ciphertext_as_view, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = abs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u64(sk);
  destroy_lwe_secret_key_unchecked_u64(deser_sk);
  destroy_lwe_ciphertext_view_unchecked_u64(ciphertext_as_view);
  destroy_lwe_ciphertext_mut_view_unchecked_u64(ciphertext_as_mut_view);
  destroy_seeder_builder_unchecked(builder);
  destroy_default_serialization_engine_unchecked(default_serialization_engine);
  destroy_default_engine_unchecked(engine);
  destroy_buffer_unchecked(&sk_buffer);
  free(ciphertext_buffer);
}

void encrypt_decrypt_raw_ptr_buffers_test(void) {
  // We generate the random sources
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &engine);
  assert(default_engine_ok == 0);
  assert(engine != NULL);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  double variance = 0.000000001;

  // We generate the key
  uint64_t lwe_dimension = 10;
  LweSecretKey64 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_u64(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  // We generate the texts
  uint64_t *ciphertext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));

  uint64_t plaintext = ((uint64_t)10) << SHIFT;

  // We encrypt the plaintext
  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
      engine, sk, ciphertext_buffer, plaintext, variance);
  assert(encrypt_ok == 0);

  // Test SK Serialization/Deserialization
  Buffer sk_buffer = {.pointer = NULL, .length = 0};
  int sk_ser_ok = default_serialization_engine_serialize_lwe_secret_key_u64(
      default_serialization_engine, sk, &sk_buffer);
  assert(sk_ser_ok == 0);

  BufferView sk_buffer_view = {.pointer = sk_buffer.pointer, .length = sk_buffer.length};
  LweSecretKey64 *deser_sk = NULL;
  int sk_deser_ok = default_serialization_engine_deserialize_lwe_secret_key_u64(
      default_serialization_engine, sk_buffer_view, &deser_sk);
  assert(sk_deser_ok == 0);

  // We decrypt the plaintext
  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_u64_raw_ptr_buffers(
      engine, deser_sk, ciphertext_buffer, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = abs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_u64(sk);
  destroy_lwe_secret_key_u64(deser_sk);
  destroy_default_serialization_engine(default_serialization_engine);
  destroy_seeder_builder(builder);
  destroy_default_engine(engine);
  destroy_buffer(&sk_buffer);
  free(ciphertext_buffer);
}

void encrypt_decrypt_unchecked_raw_ptr_buffers_test(void) {
  // We generate the random sources
  DefaultEngine *engine = NULL;
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &engine);
  assert(default_engine_ok == 0);
  assert(engine != NULL);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  double variance = 0.000000001;

  // We generate the key
  uint64_t lwe_dimension = 10;
  LweSecretKey64 *sk = NULL;
  int sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(engine, lwe_dimension, &sk);
  assert(sk_ok == 0);

  // We generate the texts
  uint64_t *ciphertext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * (lwe_dimension + 1));

  uint64_t plaintext = ((uint64_t)10) << SHIFT;

  // We encrypt the plaintext
  int encrypt_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
      engine, sk, ciphertext_buffer, plaintext, variance);
  assert(encrypt_ok == 0);

  // Test SK Serialization/Deserialization
  Buffer sk_buffer = {.pointer = NULL, .length = 0};
  int sk_ser_ok = default_serialization_engine_serialize_lwe_secret_key_u64(
      default_serialization_engine, sk, &sk_buffer);
  assert(sk_ser_ok == 0);

  BufferView sk_buffer_view = {.pointer = sk_buffer.pointer, .length = sk_buffer.length};
  LweSecretKey64 *deser_sk = NULL;
  int sk_deser_ok = default_serialization_engine_deserialize_lwe_secret_key_u64(
      default_serialization_engine, sk_buffer_view, &deser_sk);
  assert(sk_deser_ok == 0);

  // We decrypt the plaintext
  uint64_t output = -1;
  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
      engine, deser_sk, ciphertext_buffer, &output);
  assert(decrypt_ok == 0);

  // We check that the output are the same
  double expected = (double)plaintext / pow(2, SHIFT);
  double obtained = (double)output / pow(2, SHIFT);
  printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
  double abs_diff = abs(obtained - expected);
  double rel_error = abs_diff / fmax(expected, obtained);
  assert(rel_error < 0.001);

  // We deallocate the objects
  destroy_lwe_secret_key_unchecked_u64(sk);
  destroy_lwe_secret_key_unchecked_u64(deser_sk);
  destroy_seeder_builder_unchecked(builder);
  destroy_default_engine_unchecked(engine);
  destroy_buffer(&sk_buffer);
  free(ciphertext_buffer);
}

int main(void) {
  encrypt_decrypt_view_buffers_test();
  encrypt_decrypt_unchecked_view_buffers_test();
  encrypt_decrypt_raw_ptr_buffers_test();
  encrypt_decrypt_unchecked_raw_ptr_buffers_test();
  return EXIT_SUCCESS;
}
