#ifndef CNCRT_KS_H_
#define CNCRT_KS_H_

#include <cstdint>

extern "C" {

void cuda_keyswitch_lwe_ciphertext_vector_32(
    void *v_stream, uint32_t gpu_index, void *lwe_array_out, void *lwe_array_in,
    void *ksk, uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples);

void cuda_keyswitch_lwe_ciphertext_vector_64(
    void *v_stream, uint32_t gpu_index, void *lwe_array_out, void *lwe_array_in,
    void *ksk, uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples);

void cuda_fp_keyswitch_lwe_to_glwe_32(void *v_stream, void *glwe_array_out,
                                      void *lwe_array_in, void *fp_ksk_array,
                                      uint32_t input_lwe_dimension,
                                      uint32_t output_glwe_dimension,
                                      uint32_t output_polynomial_size,
                                      uint32_t base_log, uint32_t level_count,
                                      uint32_t number_of_input_lwe,
                                      uint32_t number_of_keys);

void cuda_fp_keyswitch_lwe_to_glwe_64(void *v_stream, void *glwe_array_out,
                                      void *lwe_array_in, void *fp_ksk_array,
                                      uint32_t input_lwe_dimension,
                                      uint32_t output_glwe_dimension,
                                      uint32_t output_polynomial_size,
                                      uint32_t base_log, uint32_t level_count,
                                      uint32_t number_of_input_lwe,
                                      uint32_t number_of_keys);
}

#endif // CNCRT_KS_H_
