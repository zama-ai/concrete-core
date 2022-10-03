#include "concrete-core-ffi.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

#include "utils.h"

void lwe_cbs_vp_view_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftwEngine *fftw_engine = NULL;

  int fftw_engine_ok = new_fftw_engine(&fftw_engine);
  assert(fftw_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_dimension = 481;
  size_t lwe_small_size = lwe_dimension + 1;

  size_t level_bsk = 9;
  size_t base_log_bsk = 4;

  size_t level_pksk = 9;
  size_t base_log_pksk = 4;

  size_t level_ksk = 9;
  size_t base_log_ksk = 1;

  size_t level_cbs = 4;
  size_t base_log_cbs = 6;

  double var_small = powl(2.0, -80.0);
  double var_big = powl(2.0, -70.0);

  GlweSecretKey64 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_u64(default_engine, glwe_dimension,
                                                                   polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweSecretKey64 *lwe_small_sk = NULL;
  int lwe_small_sk_ok =
      default_engine_generate_new_lwe_secret_key_u64(default_engine, lwe_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;
  size_t lwe_big_size = lwe_big_dimension + 1;

  LweSecretKey64 *lwe_big_sk = NULL;
  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok =
      clone_transform_glwe_secret_key_to_lwe_secret_key_u64(default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey64 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u64(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var_big,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_u64(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var_small, &bsk);
  assert(bsk_ok == 0);

  FftwFourierLweBootstrapKey64 *fbsk = NULL;
  int fbsk_ok = fftw_engine_convert_lwe_bootstrap_key_to_fftw_fourier_lwe_bootstrap_key_u64(
      fftw_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk = NULL;
  int cbs_pfpksk_ok =
      default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
          default_engine, lwe_big_sk, glwe_sk, base_log_pksk, level_pksk, var_small, &cbs_pfpksk);
  assert(cbs_pfpksk_ok == 0);

  // Test CBS PFPKSK Serialization/Deserialization
  Buffer cbs_pfpksk_buffer = {.pointer = NULL, .length = 0};
  int cbs_pfpksk_ser_ok =
      default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
          default_serialization_engine, cbs_pfpksk, &cbs_pfpksk_buffer);
  assert(cbs_pfpksk_ser_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk_deser = NULL;

  BufferView cbs_pfpksk_buffer_view = {.pointer = cbs_pfpksk_buffer.pointer,
                                       .length = cbs_pfpksk_buffer.length};
  int cbs_pfpksk_deser_ok =
      default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
          default_serialization_engine, cbs_pfpksk_buffer_view, &cbs_pfpksk_deser);
  assert(cbs_pfpksk_deser_ok == 0);

  // We are going to encrypt two ciphertexts with 5 bits each
  size_t number_of_bits_per_ct = 5;

  // Test on 610, binary representation 10011 00010
  uint64_t val = 610;

  uint64_t mask = ((uint64_t)1 << number_of_bits_per_ct) - 1;
  uint64_t lsb = val & mask;
  uint64_t msb = (val >> number_of_bits_per_ct) & mask;

  size_t delta_log_ciphertext = 64 - number_of_bits_per_ct;

  uint64_t msb_encoded = msb << delta_log_ciphertext;
  uint64_t lsb_encoded = lsb << delta_log_ciphertext;

  printf("msb: %" PRIu64 ", lsb: %" PRIu64 "\n", msb, lsb);

  uint64_t *input_ct_msb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);
  uint64_t *input_ct_lsb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);

  LweCiphertextMutView64 *input_ct_msb_as_mut_view = NULL;
  int input_ct_msb_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_u64(
      default_engine, input_ct_msb_buffer, lwe_big_size, &input_ct_msb_as_mut_view);
  assert(input_ct_msb_mut_view_ok == 0);

  LweCiphertextMutView64 *input_ct_lsb_as_mut_view = NULL;
  int input_ct_lsb_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_u64(
      default_engine, input_ct_lsb_buffer, lwe_big_size, &input_ct_lsb_as_mut_view);
  assert(input_ct_lsb_mut_view_ok == 0);

  int encrypt_msb_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers(
      default_engine, lwe_big_sk, input_ct_msb_as_mut_view, msb_encoded, var_big);
  assert(encrypt_msb_ok == 0);

  int encrypt_lsb_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers(
      default_engine, lwe_big_sk, input_ct_lsb_as_mut_view, lsb_encoded, var_big);
  assert(encrypt_lsb_ok == 0);

  uint64_t *extract_bits_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct * lwe_small_size);

  LweCiphertextVectorMutView64 *extract_bits_msb_output_as_mut_view = NULL;
  int msb_bits_as_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_u64(
      default_engine, extract_bits_output_buffer, lwe_small_size, number_of_bits_per_ct,
      &extract_bits_msb_output_as_mut_view);
  assert(msb_bits_as_mut_view_ok == 0);

  LweCiphertextView64 *input_ct_msb_as_view = NULL;
  int input_ct_msb_view_ok = default_engine_create_lwe_ciphertext_view_from_u64(
      default_engine, input_ct_msb_buffer, lwe_big_size, &input_ct_msb_as_view);
  assert(input_ct_msb_view_ok == 0);

  LweCiphertextVectorMutView64 *extract_bits_lsb_output_as_mut_view = NULL;
  int lsb_bits_as_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_u64(
      default_engine, &extract_bits_output_buffer[number_of_bits_per_ct * lwe_small_size],
      lwe_small_size, number_of_bits_per_ct, &extract_bits_lsb_output_as_mut_view);
  assert(lsb_bits_as_mut_view_ok == 0);

  LweCiphertextView64 *input_ct_lsb_as_view = NULL;
  int input_ct_lsb_view_ok = default_engine_create_lwe_ciphertext_view_from_u64(
      default_engine, input_ct_lsb_buffer, lwe_big_size, &input_ct_lsb_as_view);
  assert(input_ct_lsb_view_ok == 0);

  int extract_msb_ok = fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_view_buffers(
      fftw_engine, fbsk, ksk_lwe_big_to_small, extract_bits_msb_output_as_mut_view,
      input_ct_msb_as_view, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_msb_ok == 0);

  int extract_lsb_ok = fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_view_buffers(
      fftw_engine, fbsk, ksk_lwe_big_to_small, extract_bits_lsb_output_as_mut_view,
      input_ct_lsb_as_view, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_lsb_ok == 0);

  uint64_t *output_plaintext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct);

  LweCiphertextVectorView64 *extract_bits_output_as_view = NULL;
  int extract_bits_output_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_u64(
      default_engine, extract_bits_output_buffer, lwe_small_size, 2 * number_of_bits_per_ct,
      &extract_bits_output_as_view);
  assert(extract_bits_output_view_ok == 0);

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u64_view_buffers(
      default_engine, lwe_small_sk, extract_bits_output_as_view, output_plaintext_buffer);

  assert(decrypt_ok == 0);

  // Decryption of extracted bits for sanity check
  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (msb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (lsb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded =
        closest_representable(output_plaintext_buffer[idx + number_of_bits_per_ct], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  // We'll apply a single table look-up computing x + 1 to our 10 bits input integer that was
  // represented over two 5 bits ciphertexts
  size_t number_of_luts_and_output_cts = 1;

  uint64_t *cbs_vp_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size * number_of_luts_and_output_cts);

  LweCiphertextVectorMutView64 *cbs_vp_output_as_mut_view = NULL;
  int cbs_vp_output_mut_view_ok = default_engine_create_lwe_ciphertext_vector_mut_view_from_u64(
      default_engine, cbs_vp_output_buffer, lwe_big_size, number_of_luts_and_output_cts,
      &cbs_vp_output_as_mut_view);
  assert(cbs_vp_output_mut_view_ok == 0);

  // Here we will create a single lut containing a single polynomial, which will result in a single
  // Output ciphertecct

  size_t luts_length = number_of_luts_and_output_cts * polynomial_size;
  uint64_t *luts = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * luts_length);

  size_t delta_log_lut = 64 - 2 * number_of_bits_per_ct;

  for (size_t idx = 0; idx < luts_length; ++idx) {
    luts[idx] = ((idx + 1) % ((uint64_t)1 << (2 * number_of_bits_per_ct))) << delta_log_lut;
  }

  int cbs_vp_ok =
      fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_view_buffers(
          fftw_engine, default_engine, fbsk, cbs_vp_output_as_mut_view, extract_bits_output_as_view,
          luts, luts_length, level_cbs, base_log_cbs, cbs_pfpksk_deser);
  assert(cbs_vp_ok == 0);

  LweCiphertextVectorView64 *cbs_vp_output_as_view = NULL;
  int cbs_vp_output_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_u64(
      default_engine, cbs_vp_output_buffer, lwe_big_size, number_of_luts_and_output_cts,
      &cbs_vp_output_as_view);
  assert(cbs_vp_output_view_ok == 0);

  uint64_t *cbs_vp_decryption_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * number_of_luts_and_output_cts);

  int result_decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u64_view_buffers(
      default_engine, lwe_big_sk, cbs_vp_output_as_view, cbs_vp_decryption_buffer);
  assert(result_decrypt_ok == 0);

  uint64_t expected = val + 1;
  uint64_t rounded =
      closest_representable(cbs_vp_decryption_buffer[0], 1, 2 * number_of_bits_per_ct);
  uint64_t decrypted = rounded >> delta_log_lut;
  printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
  assert(decrypted == expected);

  destroy_lwe_ciphertext_vector_view_u64(cbs_vp_output_as_view);
  destroy_lwe_ciphertext_vector_mut_view_u64(cbs_vp_output_as_mut_view);
  destroy_lwe_ciphertext_vector_view_u64(extract_bits_output_as_view);
  destroy_lwe_ciphertext_view_u64(input_ct_lsb_as_view);
  destroy_lwe_ciphertext_view_u64(input_ct_msb_as_view);
  destroy_lwe_ciphertext_vector_mut_view_u64(extract_bits_lsb_output_as_mut_view);
  destroy_lwe_ciphertext_vector_mut_view_u64(extract_bits_msb_output_as_mut_view);
  destroy_lwe_ciphertext_mut_view_u64(input_ct_lsb_as_mut_view);
  destroy_lwe_ciphertext_mut_view_u64(input_ct_msb_as_mut_view);
  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(cbs_pfpksk_deser);
  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(cbs_pfpksk);
  destroy_fftw_fourier_lwe_bootstrap_key_u64(fbsk);
  destroy_lwe_bootstrap_key_u64(bsk);
  destroy_lwe_keyswitch_key_u64(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_u64(lwe_big_sk);
  destroy_lwe_secret_key_u64(lwe_small_sk);
  destroy_glwe_secret_key_u64(glwe_sk);
  destroy_default_serialization_engine(default_serialization_engine);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_fftw_engine(fftw_engine);
  destroy_seeder_builder(builder);
  destroy_buffer(&cbs_pfpksk_buffer);
  free(input_ct_msb_buffer);
  free(input_ct_lsb_buffer);
  free(output_plaintext_buffer);
  free(extract_bits_output_buffer);
  free(cbs_vp_output_buffer);
  free(luts);
  free(cbs_vp_decryption_buffer);
}

void lwe_cbs_vp_unchecked_view_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine_unchecked(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftwEngine *fftw_engine = NULL;

  int fftw_engine_ok = new_fftw_engine_unchecked(&fftw_engine);
  assert(fftw_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_dimension = 481;
  size_t lwe_small_size = lwe_dimension + 1;

  size_t level_bsk = 9;
  size_t base_log_bsk = 4;

  size_t level_pksk = 9;
  size_t base_log_pksk = 4;

  size_t level_ksk = 9;
  size_t base_log_ksk = 1;

  size_t level_cbs = 4;
  size_t base_log_cbs = 6;

  double var_small = powl(2.0, -80.0);
  double var_big = powl(2.0, -70.0);

  GlweSecretKey64 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_unchecked_u64(
      default_engine, glwe_dimension, polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweSecretKey64 *lwe_small_sk = NULL;
  int lwe_small_sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, lwe_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;
  size_t lwe_big_size = lwe_big_dimension + 1;

  LweSecretKey64 *lwe_big_sk = NULL;
  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u64(
      default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey64 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u64(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var_big,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_unchecked_u64(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var_small, &bsk);
  assert(bsk_ok == 0);

  FftwFourierLweBootstrapKey64 *fbsk = NULL;
  int fbsk_ok =
      fftw_engine_convert_lwe_bootstrap_key_to_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
          fftw_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk = NULL;
  int cbs_pfpksk_ok =
      default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
          default_engine, lwe_big_sk, glwe_sk, base_log_pksk, level_pksk, var_small, &cbs_pfpksk);
  assert(cbs_pfpksk_ok == 0);

  // Test CBS PFPKSK Serialization/Deserialization
  Buffer cbs_pfpksk_buffer = {.pointer = NULL, .length = 0};
  int cbs_pfpksk_ser_ok =
      default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
          default_serialization_engine, cbs_pfpksk, &cbs_pfpksk_buffer);
  assert(cbs_pfpksk_ser_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk_deser = NULL;

  BufferView cbs_pfpksk_buffer_view = {.pointer = cbs_pfpksk_buffer.pointer,
                                       .length = cbs_pfpksk_buffer.length};
  int cbs_pfpksk_deser_ok =
      default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
          default_serialization_engine, cbs_pfpksk_buffer_view, &cbs_pfpksk_deser);
  assert(cbs_pfpksk_deser_ok == 0);

  // We are going to encrypt two ciphertexts with 5 bits each
  size_t number_of_bits_per_ct = 5;

  // Test on 610, binary representation 10011 00010
  uint64_t val = 610;

  uint64_t mask = ((uint64_t)1 << number_of_bits_per_ct) - 1;
  uint64_t lsb = val & mask;
  uint64_t msb = (val >> number_of_bits_per_ct) & mask;

  size_t delta_log_ciphertext = 64 - number_of_bits_per_ct;

  uint64_t msb_encoded = msb << delta_log_ciphertext;
  uint64_t lsb_encoded = lsb << delta_log_ciphertext;

  printf("msb: %" PRIu64 ", lsb: %" PRIu64 "\n", msb, lsb);

  uint64_t *input_ct_msb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);
  uint64_t *input_ct_lsb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);

  LweCiphertextMutView64 *input_ct_msb_as_mut_view = NULL;
  int input_ct_msb_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_unchecked_u64(
      default_engine, input_ct_msb_buffer, lwe_big_size, &input_ct_msb_as_mut_view);
  assert(input_ct_msb_mut_view_ok == 0);

  LweCiphertextMutView64 *input_ct_lsb_as_mut_view = NULL;
  int input_ct_lsb_mut_view_ok = default_engine_create_lwe_ciphertext_mut_view_from_unchecked_u64(
      default_engine, input_ct_lsb_buffer, lwe_big_size, &input_ct_lsb_as_mut_view);
  assert(input_ct_lsb_mut_view_ok == 0);

  int encrypt_msb_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_view_buffers(
      default_engine, lwe_big_sk, input_ct_msb_as_mut_view, msb_encoded, var_big);
  assert(encrypt_msb_ok == 0);

  int encrypt_lsb_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_view_buffers(
      default_engine, lwe_big_sk, input_ct_lsb_as_mut_view, lsb_encoded, var_big);
  assert(encrypt_lsb_ok == 0);

  uint64_t *extract_bits_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct * lwe_small_size);

  LweCiphertextVectorMutView64 *extract_bits_msb_output_as_mut_view = NULL;
  int msb_bits_as_mut_view_ok =
      default_engine_create_lwe_ciphertext_vector_mut_view_from_unchecked_u64(
          default_engine, extract_bits_output_buffer, lwe_small_size, number_of_bits_per_ct,
          &extract_bits_msb_output_as_mut_view);
  assert(msb_bits_as_mut_view_ok == 0);

  LweCiphertextView64 *input_ct_msb_as_view = NULL;
  int input_ct_msb_view_ok = default_engine_create_lwe_ciphertext_view_from_unchecked_u64(
      default_engine, input_ct_msb_buffer, lwe_big_size, &input_ct_msb_as_view);
  assert(input_ct_msb_view_ok == 0);

  LweCiphertextVectorMutView64 *extract_bits_lsb_output_as_mut_view = NULL;
  int lsb_bits_as_mut_view_ok =
      default_engine_create_lwe_ciphertext_vector_mut_view_from_unchecked_u64(
          default_engine, &extract_bits_output_buffer[number_of_bits_per_ct * lwe_small_size],
          lwe_small_size, number_of_bits_per_ct, &extract_bits_lsb_output_as_mut_view);
  assert(lsb_bits_as_mut_view_ok == 0);

  LweCiphertextView64 *input_ct_lsb_as_view = NULL;
  int input_ct_lsb_view_ok = default_engine_create_lwe_ciphertext_view_from_unchecked_u64(
      default_engine, input_ct_lsb_buffer, lwe_big_size, &input_ct_lsb_as_view);
  assert(input_ct_lsb_view_ok == 0);

  int extract_msb_ok =
      fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_view_buffers(
          fftw_engine, fbsk, ksk_lwe_big_to_small, extract_bits_msb_output_as_mut_view,
          input_ct_msb_as_view, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_msb_ok == 0);

  int extract_lsb_ok =
      fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_view_buffers(
          fftw_engine, fbsk, ksk_lwe_big_to_small, extract_bits_lsb_output_as_mut_view,
          input_ct_lsb_as_view, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_lsb_ok == 0);

  uint64_t *output_plaintext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct);

  LweCiphertextVectorView64 *extract_bits_output_as_view = NULL;
  int extract_bits_output_view_ok =
      default_engine_create_lwe_ciphertext_vector_view_from_unchecked_u64(
          default_engine, extract_bits_output_buffer, lwe_small_size, 2 * number_of_bits_per_ct,
          &extract_bits_output_as_view);
  assert(extract_bits_output_view_ok == 0);

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u64_view_buffers(
      default_engine, lwe_small_sk, extract_bits_output_as_view, output_plaintext_buffer);

  assert(decrypt_ok == 0);

  // Decryption of extracted bits for sanity check
  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (msb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (lsb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded =
        closest_representable(output_plaintext_buffer[idx + number_of_bits_per_ct], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  // We'll apply a single table look-up computing x + 1 to our 10 bits input integer that was
  // represented over two 5 bits ciphertexts
  size_t number_of_luts_and_output_cts = 1;

  uint64_t *cbs_vp_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size * number_of_luts_and_output_cts);

  LweCiphertextVectorMutView64 *cbs_vp_output_as_mut_view = NULL;
  int cbs_vp_output_mut_view_ok =
      default_engine_create_lwe_ciphertext_vector_mut_view_from_unchecked_u64(
          default_engine, cbs_vp_output_buffer, lwe_big_size, number_of_luts_and_output_cts,
          &cbs_vp_output_as_mut_view);
  assert(cbs_vp_output_mut_view_ok == 0);

  // Here we will create a single lut containing a single polynomial, which will result in a single
  // Output ciphertecct

  size_t luts_length = number_of_luts_and_output_cts * polynomial_size;
  uint64_t *luts = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * luts_length);

  size_t delta_log_lut = 64 - 2 * number_of_bits_per_ct;

  for (size_t idx = 0; idx < luts_length; ++idx) {
    luts[idx] = ((idx + 1) % ((uint64_t)1 << (2 * number_of_bits_per_ct))) << delta_log_lut;
  }

  int cbs_vp_ok =
      fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_unchecked_u64_view_buffers(
          fftw_engine, default_engine, fbsk, cbs_vp_output_as_mut_view, extract_bits_output_as_view,
          luts, luts_length, level_cbs, base_log_cbs, cbs_pfpksk_deser);
  assert(cbs_vp_ok == 0);

  LweCiphertextVectorView64 *cbs_vp_output_as_view = NULL;
  int cbs_vp_output_view_ok = default_engine_create_lwe_ciphertext_vector_view_from_unchecked_u64(
      default_engine, cbs_vp_output_buffer, lwe_big_size, number_of_luts_and_output_cts,
      &cbs_vp_output_as_view);
  assert(cbs_vp_output_view_ok == 0);

  uint64_t *cbs_vp_decryption_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * number_of_luts_and_output_cts);

  int result_decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u64_view_buffers(
      default_engine, lwe_big_sk, cbs_vp_output_as_view, cbs_vp_decryption_buffer);
  assert(result_decrypt_ok == 0);

  uint64_t expected = val + 1;
  uint64_t rounded =
      closest_representable(cbs_vp_decryption_buffer[0], 1, 2 * number_of_bits_per_ct);
  uint64_t decrypted = rounded >> delta_log_lut;
  printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
  assert(decrypted == expected);

  destroy_lwe_ciphertext_vector_view_unchecked_u64(cbs_vp_output_as_view);
  destroy_lwe_ciphertext_vector_mut_view_unchecked_u64(cbs_vp_output_as_mut_view);
  destroy_lwe_ciphertext_vector_view_unchecked_u64(extract_bits_output_as_view);
  destroy_lwe_ciphertext_view_unchecked_u64(input_ct_lsb_as_view);
  destroy_lwe_ciphertext_view_unchecked_u64(input_ct_msb_as_view);
  destroy_lwe_ciphertext_vector_mut_view_unchecked_u64(extract_bits_lsb_output_as_mut_view);
  destroy_lwe_ciphertext_vector_mut_view_unchecked_u64(extract_bits_msb_output_as_mut_view);
  destroy_lwe_ciphertext_mut_view_unchecked_u64(input_ct_lsb_as_mut_view);
  destroy_lwe_ciphertext_mut_view_unchecked_u64(input_ct_msb_as_mut_view);
  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
      cbs_pfpksk_deser);
  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(cbs_pfpksk);
  destroy_fftw_fourier_lwe_bootstrap_key_unchecked_u64(fbsk);
  destroy_lwe_bootstrap_key_unchecked_u64(bsk);
  destroy_lwe_keyswitch_key_unchecked_u64(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_unchecked_u64(lwe_big_sk);
  destroy_lwe_secret_key_unchecked_u64(lwe_small_sk);
  destroy_glwe_secret_key_unchecked_u64(glwe_sk);
  destroy_default_serialization_engine_unchecked(default_serialization_engine);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fftw_engine_unchecked(fftw_engine);
  destroy_seeder_builder_unchecked(builder);
  destroy_buffer_unchecked(&cbs_pfpksk_buffer);
  free(input_ct_msb_buffer);
  free(input_ct_lsb_buffer);
  free(output_plaintext_buffer);
  free(extract_bits_output_buffer);
  free(cbs_vp_output_buffer);
  free(luts);
  free(cbs_vp_decryption_buffer);
}

void lwe_cbs_vp_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder();

  int default_engine_ok = new_default_engine(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok = new_default_parallel_engine(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftwEngine *fftw_engine = NULL;

  int fftw_engine_ok = new_fftw_engine(&fftw_engine);
  assert(fftw_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_dimension = 481;
  size_t lwe_small_size = lwe_dimension + 1;

  size_t level_bsk = 9;
  size_t base_log_bsk = 4;

  size_t level_pksk = 9;
  size_t base_log_pksk = 4;

  size_t level_ksk = 9;
  size_t base_log_ksk = 1;

  size_t level_cbs = 4;
  size_t base_log_cbs = 6;

  double var_small = powl(2.0, -80.0);
  double var_big = powl(2.0, -70.0);

  GlweSecretKey64 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_u64(default_engine, glwe_dimension,
                                                                   polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweSecretKey64 *lwe_small_sk = NULL;
  int lwe_small_sk_ok =
      default_engine_generate_new_lwe_secret_key_u64(default_engine, lwe_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;
  size_t lwe_big_size = lwe_big_dimension + 1;

  LweSecretKey64 *lwe_big_sk = NULL;
  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok =
      clone_transform_glwe_secret_key_to_lwe_secret_key_u64(default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey64 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_u64(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var_big,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_u64(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var_small, &bsk);
  assert(bsk_ok == 0);

  FftwFourierLweBootstrapKey64 *fbsk = NULL;
  int fbsk_ok = fftw_engine_convert_lwe_bootstrap_key_to_fftw_fourier_lwe_bootstrap_key_u64(
      fftw_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk = NULL;
  int cbs_pfpksk_ok =
      default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
          default_engine, lwe_big_sk, glwe_sk, base_log_pksk, level_pksk, var_small, &cbs_pfpksk);
  assert(cbs_pfpksk_ok == 0);

  // Test CBS PFPKSK Serialization/Deserialization
  Buffer cbs_pfpksk_buffer = {.pointer = NULL, .length = 0};
  int cbs_pfpksk_ser_ok =
      default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
          default_serialization_engine, cbs_pfpksk, &cbs_pfpksk_buffer);
  assert(cbs_pfpksk_ser_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk_deser = NULL;

  BufferView cbs_pfpksk_buffer_view = {.pointer = cbs_pfpksk_buffer.pointer,
                                       .length = cbs_pfpksk_buffer.length};
  int cbs_pfpksk_deser_ok =
      default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
          default_serialization_engine, cbs_pfpksk_buffer_view, &cbs_pfpksk_deser);
  assert(cbs_pfpksk_deser_ok == 0);

  // We are going to encrypt two ciphertexts with 5 bits each
  size_t number_of_bits_per_ct = 5;

  // Test on 610, binary representation 10011 00010
  uint64_t val = 610;

  uint64_t mask = ((uint64_t)1 << number_of_bits_per_ct) - 1;
  uint64_t lsb = val & mask;
  uint64_t msb = (val >> number_of_bits_per_ct) & mask;

  size_t delta_log_ciphertext = 64 - number_of_bits_per_ct;

  uint64_t msb_encoded = msb << delta_log_ciphertext;
  uint64_t lsb_encoded = lsb << delta_log_ciphertext;

  printf("msb: %" PRIu64 ", lsb: %" PRIu64 "\n", msb, lsb);

  uint64_t *input_ct_msb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);
  uint64_t *input_ct_lsb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);

  int encrypt_msb_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
      default_engine, lwe_big_sk, input_ct_msb_buffer, msb_encoded, var_big);
  assert(encrypt_msb_ok == 0);

  int encrypt_lsb_ok = default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
      default_engine, lwe_big_sk, input_ct_lsb_buffer, lsb_encoded, var_big);
  assert(encrypt_lsb_ok == 0);

  uint64_t *extract_bits_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct * lwe_small_size);
  uint64_t *extract_bits_output_buffer_lsb =
      &extract_bits_output_buffer[number_of_bits_per_ct * lwe_small_size];

  int extract_msb_ok = fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_raw_ptr_buffers(
      fftw_engine, default_engine, fbsk, ksk_lwe_big_to_small, extract_bits_output_buffer,
      input_ct_msb_buffer, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_msb_ok == 0);

  int extract_lsb_ok = fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_raw_ptr_buffers(
      fftw_engine, default_engine, fbsk, ksk_lwe_big_to_small, extract_bits_output_buffer_lsb,
      input_ct_lsb_buffer, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_lsb_ok == 0);

  uint64_t *output_plaintext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct);

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u64_raw_ptr_buffers(
      default_engine, lwe_small_sk, extract_bits_output_buffer, output_plaintext_buffer,
      2 * number_of_bits_per_ct);

  assert(decrypt_ok == 0);

  // Decryption of extracted bits for sanity check
  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (msb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (lsb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded =
        closest_representable(output_plaintext_buffer[idx + number_of_bits_per_ct], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  // We'll apply a single table look-up computing x + 1 to our 10 bits input integer that was
  // represented over two 5 bits ciphertexts
  size_t number_of_luts_and_output_cts = 1;

  uint64_t *cbs_vp_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size * number_of_luts_and_output_cts);

  // Here we will create a single lut containing a single polynomial, which will result in a single
  // Output ciphertecct

  size_t luts_length = number_of_luts_and_output_cts * polynomial_size;
  uint64_t *luts = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * luts_length);

  size_t delta_log_lut = 64 - 2 * number_of_bits_per_ct;

  for (size_t idx = 0; idx < luts_length; ++idx) {
    luts[idx] = ((idx + 1) % ((uint64_t)1 << (2 * number_of_bits_per_ct))) << delta_log_lut;
  }

  int cbs_vp_ok =
      fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_raw_ptr_buffers(
          fftw_engine, default_engine, fbsk, cbs_vp_output_buffer, lwe_big_size,
          number_of_luts_and_output_cts, extract_bits_output_buffer, lwe_small_size,
          2 * number_of_bits_per_ct, luts, luts_length, level_cbs, base_log_cbs, cbs_pfpksk_deser);
  assert(cbs_vp_ok == 0);

  uint64_t *cbs_vp_decryption_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * number_of_luts_and_output_cts);

  int result_decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_u64_raw_ptr_buffers(
      default_engine, lwe_big_sk, cbs_vp_output_buffer, cbs_vp_decryption_buffer,
      number_of_luts_and_output_cts);
  assert(result_decrypt_ok == 0);

  uint64_t expected = val + 1;
  uint64_t rounded =
      closest_representable(cbs_vp_decryption_buffer[0], 1, 2 * number_of_bits_per_ct);
  uint64_t decrypted = rounded >> delta_log_lut;
  printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
  assert(decrypted == expected);

  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(cbs_pfpksk_deser);
  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(cbs_pfpksk);
  destroy_fftw_fourier_lwe_bootstrap_key_u64(fbsk);
  destroy_lwe_bootstrap_key_u64(bsk);
  destroy_lwe_keyswitch_key_u64(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_u64(lwe_big_sk);
  destroy_lwe_secret_key_u64(lwe_small_sk);
  destroy_glwe_secret_key_u64(glwe_sk);
  destroy_default_serialization_engine(default_serialization_engine);
  destroy_default_parallel_engine(default_parallel_engine);
  destroy_default_engine(default_engine);
  destroy_fftw_engine(fftw_engine);
  destroy_seeder_builder(builder);
  destroy_buffer(&cbs_pfpksk_buffer);
  free(input_ct_msb_buffer);
  free(input_ct_lsb_buffer);
  free(output_plaintext_buffer);
  free(extract_bits_output_buffer);
  free(cbs_vp_output_buffer);
  free(luts);
  free(cbs_vp_decryption_buffer);
}

void lwe_cbs_vp_unchecked_raw_ptr_buffers_test(void) {
  DefaultEngine *default_engine = NULL;
  // DANGER IN THE GENERAL CASE YOU WANT A SEEDER PER ENGINE, THIS IS FOR TESTING ONLY
  SeederBuilder *builder = get_best_seeder_unchecked();

  int default_engine_ok = new_default_engine_unchecked(builder, &default_engine);
  assert(default_engine_ok == 0);

  DefaultSerializationEngine *default_serialization_engine = NULL;

  int default_serialization_engine_ok =
      new_default_serialization_engine_unchecked(&default_serialization_engine);
  assert(default_serialization_engine_ok == 0);

  DefaultParallelEngine *default_parallel_engine = NULL;

  int default_parallel_engine_ok =
      new_default_parallel_engine_unchecked(builder, &default_parallel_engine);
  assert(default_parallel_engine_ok == 0);

  FftwEngine *fftw_engine = NULL;

  int fftw_engine_ok = new_fftw_engine_unchecked(&fftw_engine);
  assert(fftw_engine_ok == 0);

  size_t polynomial_size = 1024;
  size_t glwe_dimension = 1;
  size_t lwe_dimension = 481;
  size_t lwe_small_size = lwe_dimension + 1;

  size_t level_bsk = 9;
  size_t base_log_bsk = 4;

  size_t level_pksk = 9;
  size_t base_log_pksk = 4;

  size_t level_ksk = 9;
  size_t base_log_ksk = 1;

  size_t level_cbs = 4;
  size_t base_log_cbs = 6;

  double var_small = powl(2.0, -80.0);
  double var_big = powl(2.0, -70.0);

  GlweSecretKey64 *glwe_sk = NULL;
  int glwe_sk_ok = default_engine_generate_new_glwe_secret_key_unchecked_u64(
      default_engine, glwe_dimension, polynomial_size, &glwe_sk);
  assert(glwe_sk_ok == 0);

  LweSecretKey64 *lwe_small_sk = NULL;
  int lwe_small_sk_ok = default_engine_generate_new_lwe_secret_key_unchecked_u64(
      default_engine, lwe_dimension, &lwe_small_sk);
  assert(lwe_small_sk_ok == 0);

  size_t lwe_big_dimension = polynomial_size * glwe_dimension;
  size_t lwe_big_size = lwe_big_dimension + 1;

  LweSecretKey64 *lwe_big_sk = NULL;
  // This is not part of the C FFI but rather is a C util exposed for convenience in tests.
  int clone_transform_ok = clone_transform_glwe_secret_key_to_lwe_secret_key_unchecked_u64(
      default_engine, glwe_sk, &lwe_big_sk);
  assert(clone_transform_ok == 0);

  LweKeyswitchKey64 *ksk_lwe_big_to_small = NULL;
  int ksk_ok = default_engine_generate_new_lwe_keyswitch_key_unchecked_u64(
      default_engine, lwe_big_sk, lwe_small_sk, level_ksk, base_log_ksk, var_big,
      &ksk_lwe_big_to_small);
  assert(ksk_ok == 0);

  LweBootstrapKey64 *bsk = NULL;
  int bsk_ok = default_parallel_engine_generate_new_lwe_bootstrap_key_unchecked_u64(
      default_parallel_engine, lwe_small_sk, glwe_sk, base_log_bsk, level_bsk, var_small, &bsk);
  assert(bsk_ok == 0);

  FftwFourierLweBootstrapKey64 *fbsk = NULL;
  int fbsk_ok =
      fftw_engine_convert_lwe_bootstrap_key_to_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
          fftw_engine, bsk, &fbsk);
  assert(fbsk_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk = NULL;
  int cbs_pfpksk_ok =
      default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
          default_engine, lwe_big_sk, glwe_sk, base_log_pksk, level_pksk, var_small, &cbs_pfpksk);
  assert(cbs_pfpksk_ok == 0);

  // Test CBS PFPKSK Serialization/Deserialization
  Buffer cbs_pfpksk_buffer = {.pointer = NULL, .length = 0};
  int cbs_pfpksk_ser_ok =
      default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
          default_serialization_engine, cbs_pfpksk, &cbs_pfpksk_buffer);
  assert(cbs_pfpksk_ser_ok == 0);

  LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 *cbs_pfpksk_deser = NULL;

  BufferView cbs_pfpksk_buffer_view = {.pointer = cbs_pfpksk_buffer.pointer,
                                       .length = cbs_pfpksk_buffer.length};
  int cbs_pfpksk_deser_ok =
      default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
          default_serialization_engine, cbs_pfpksk_buffer_view, &cbs_pfpksk_deser);
  assert(cbs_pfpksk_deser_ok == 0);

  // We are going to encrypt two ciphertexts with 5 bits each
  size_t number_of_bits_per_ct = 5;

  // Test on 610, binary representation 10011 00010
  uint64_t val = 610;

  uint64_t mask = ((uint64_t)1 << number_of_bits_per_ct) - 1;
  uint64_t lsb = val & mask;
  uint64_t msb = (val >> number_of_bits_per_ct) & mask;

  size_t delta_log_ciphertext = 64 - number_of_bits_per_ct;

  uint64_t msb_encoded = msb << delta_log_ciphertext;
  uint64_t lsb_encoded = lsb << delta_log_ciphertext;

  printf("msb: %" PRIu64 ", lsb: %" PRIu64 "\n", msb, lsb);

  uint64_t *input_ct_msb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);
  uint64_t *input_ct_lsb_buffer = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size);

  int encrypt_msb_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
      default_engine, lwe_big_sk, input_ct_msb_buffer, msb_encoded, var_big);
  assert(encrypt_msb_ok == 0);

  int encrypt_lsb_ok = default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
      default_engine, lwe_big_sk, input_ct_lsb_buffer, lsb_encoded, var_big);
  assert(encrypt_lsb_ok == 0);

  uint64_t *extract_bits_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct * lwe_small_size);
  uint64_t *extract_bits_output_buffer_lsb =
      &extract_bits_output_buffer[number_of_bits_per_ct * lwe_small_size];

  int extract_msb_ok =
      fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_raw_ptr_buffers(
          fftw_engine, default_engine, fbsk, ksk_lwe_big_to_small, extract_bits_output_buffer,
          input_ct_msb_buffer, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_msb_ok == 0);

  int extract_lsb_ok =
      fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_raw_ptr_buffers(
          fftw_engine, default_engine, fbsk, ksk_lwe_big_to_small, extract_bits_output_buffer_lsb,
          input_ct_lsb_buffer, number_of_bits_per_ct, delta_log_ciphertext);
  assert(extract_lsb_ok == 0);

  uint64_t *output_plaintext_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * 2 * number_of_bits_per_ct);

  int decrypt_ok = default_engine_decrypt_lwe_ciphertext_vector_unchecked_u64_raw_ptr_buffers(
      default_engine, lwe_small_sk, extract_bits_output_buffer, output_plaintext_buffer,
      2 * number_of_bits_per_ct);

  assert(decrypt_ok == 0);

  // Decryption of extracted bits for sanity check
  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (msb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded = closest_representable(output_plaintext_buffer[idx], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  for (size_t idx = 0; idx < number_of_bits_per_ct; ++idx) {
    uint64_t expected =
        (lsb_encoded >> (delta_log_ciphertext + number_of_bits_per_ct - 1 - idx)) & 1;
    uint64_t rounded =
        closest_representable(output_plaintext_buffer[idx + number_of_bits_per_ct], 1, 1);
    uint64_t decrypted = rounded >> 63;
    printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
    assert(decrypted == expected);
  }

  // We'll apply a single table look-up computing x + 1 to our 10 bits input integer that was
  // represented over two 5 bits ciphertexts
  size_t number_of_luts_and_output_cts = 1;

  uint64_t *cbs_vp_output_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * lwe_big_size * number_of_luts_and_output_cts);

  // Here we will create a single lut containing a single polynomial, which will result in a single
  // Output ciphertecct

  size_t luts_length = number_of_luts_and_output_cts * polynomial_size;
  uint64_t *luts = aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * luts_length);

  size_t delta_log_lut = 64 - 2 * number_of_bits_per_ct;

  for (size_t idx = 0; idx < luts_length; ++idx) {
    luts[idx] = ((idx + 1) % ((uint64_t)1 << (2 * number_of_bits_per_ct))) << delta_log_lut;
  }

  int cbs_vp_ok =
      fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_unchecked_u64_raw_ptr_buffers(
          fftw_engine, default_engine, fbsk, cbs_vp_output_buffer, lwe_big_size,
          number_of_luts_and_output_cts, extract_bits_output_buffer, lwe_small_size,
          2 * number_of_bits_per_ct, luts, luts_length, level_cbs, base_log_cbs, cbs_pfpksk_deser);
  assert(cbs_vp_ok == 0);

  uint64_t *cbs_vp_decryption_buffer =
      aligned_alloc(U64_ALIGNMENT, sizeof(uint64_t) * number_of_luts_and_output_cts);

  int result_decrypt_ok =
      default_engine_decrypt_lwe_ciphertext_vector_unchecked_u64_raw_ptr_buffers(
          default_engine, lwe_big_sk, cbs_vp_output_buffer, cbs_vp_decryption_buffer,
          number_of_luts_and_output_cts);
  assert(result_decrypt_ok == 0);

  uint64_t expected = val + 1;
  uint64_t rounded =
      closest_representable(cbs_vp_decryption_buffer[0], 1, 2 * number_of_bits_per_ct);
  uint64_t decrypted = rounded >> delta_log_lut;
  printf("decrypted %" PRIu64 ", expected %" PRIu64 "\n", decrypted, expected);
  assert(decrypted == expected);

  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
      cbs_pfpksk_deser);
  destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(cbs_pfpksk);
  destroy_fftw_fourier_lwe_bootstrap_key_unchecked_u64(fbsk);
  destroy_lwe_bootstrap_key_unchecked_u64(bsk);
  destroy_lwe_keyswitch_key_unchecked_u64(ksk_lwe_big_to_small);
  destroy_lwe_secret_key_unchecked_u64(lwe_big_sk);
  destroy_lwe_secret_key_unchecked_u64(lwe_small_sk);
  destroy_glwe_secret_key_unchecked_u64(glwe_sk);
  destroy_default_serialization_engine_unchecked(default_serialization_engine);
  destroy_default_parallel_engine_unchecked(default_parallel_engine);
  destroy_default_engine_unchecked(default_engine);
  destroy_fftw_engine_unchecked(fftw_engine);
  destroy_seeder_builder_unchecked(builder);
  destroy_buffer_unchecked(&cbs_pfpksk_buffer);
  free(input_ct_msb_buffer);
  free(input_ct_lsb_buffer);
  free(output_plaintext_buffer);
  free(extract_bits_output_buffer);
  free(cbs_vp_output_buffer);
  free(luts);
  free(cbs_vp_decryption_buffer);
}

int main(void) {
  lwe_cbs_vp_view_buffers_test();
  lwe_cbs_vp_unchecked_view_buffers_test();
  lwe_cbs_vp_raw_ptr_buffers_test();
  lwe_cbs_vp_unchecked_raw_ptr_buffers_test();
  return EXIT_SUCCESS;
}
