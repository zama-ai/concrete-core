#include "bootstrap_amortized.cuh"

/* Perform bootstrapping on a batch of input LWE ciphertexts
 *
 *  - lwe_array_out: output batch of num_samples bootstrapped ciphertexts c =
 * (a0,..an-1,b) where n is the LWE dimension
 *  - lut_vector: should hold as many test vectors of size polynomial_size
 * as there are input ciphertexts, but actually holds
 * num_lut_vectors vectors to reduce memory usage
 *  - lut_vector_indexes: stores the index corresponding to
 * which test vector to use for each sample in
 * lut_vector
 *  - lwe_array_in: input batch of num_samples LWE ciphertexts, containing n
 * mask values + 1 body value
 *  - bootstrapping_key: RGSW encryption of the LWE secret key sk1
 * under secret key sk2
 * bsk = Z + sk1 H
 * where H is the gadget matrix and Z is a matrix (k+1).l
 * containing GLWE encryptions of 0 under sk2.
 * bsk is thus a tensor of size (k+1)^2.l.N.n
 * where l is the number of decomposition levels and
 * k is the GLWE dimension, N is the polynomial size for
 * GLWE. The polynomial size for GLWE and the test vector
 * are the same because they have to be in the same ring
 * to be multiplied.
 * Note: it is necessary to generate (k+1).k.l.N.n
 * uniformly random coefficients for the zero encryptions
 * - input_lwe_dimension: size of the Torus vector used to encrypt the input
 * LWE ciphertexts - referred to as n above (~ 600)
 * - polynomial_size: size of the test polynomial (test vector) and size of the
 * GLWE polynomial (~1024)
 * - base_log: log base used for the gadget matrix - B = 2^base_log (~8)
 * - level_count: number of decomposition levels in the gadget matrix (~4)
 * - num_samples: number of encrypted input messages
 * - num_lut_vectors: parameter to set the actual number of test vectors to be
 * used
 * - q: number of bytes in the integer representation (32 or 64)
 *
 * This function calls a wrapper to a device kernel that performs the
 * bootstrapping:
 * 	- the kernel is templatized based on integer discretization and
 * polynomial degree
 * 	- num_samples blocks of threads are launched, where each thread is going
 * to handle one or more polynomial coefficients at each stage:
 * 		- perform the blind rotation
 * 		- round the result
 * 		- decompose into level_count levels, then for each level:
 * 		  - switch to the FFT domain
 * 		  - multiply with the bootstrapping key
 * 		  - come back to the coefficients representation
 * 	- between each stage a synchronization of the threads is necessary
 * 	- in case the device has enough shared memory, temporary arrays used for
 * the different stages (accumulators) are stored into the shared memory
 * 	- the accumulators serve to combine the results for all decomposition
 * levels
 * 	- the constant memory (64K) is used for storing the roots of identity
 * values for the FFT
 */

void cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
    void *v_stream, void *lwe_array_out, void *lut_vector,
    void *lut_vector_indexes, void *lwe_array_in, void *bootstrapping_key,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_lut_vectors, uint32_t lwe_idx, uint32_t max_shared_memory) {

  assert(
      ("Error (GPU amortized PBS): base log should be <= 8", base_log <= 8));
  assert(("Error (GPU amortized PBS): glwe_dimension should be equal to 1",
          glwe_dimension == 1));
  assert(("Error (GPU amortized PBS): polynomial size should be one of 512, "
          "1024, 2048, 4096, 8192",
          polynomial_size == 512 || polynomial_size == 1024 ||
              polynomial_size == 2048 || polynomial_size == 4096 ||
              polynomial_size == 8192));

  switch (polynomial_size) {
  case 512:
    host_bootstrap_amortized<uint32_t, Degree<512>>(
        v_stream, (uint32_t *)lwe_array_out, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 1024:
    host_bootstrap_amortized<uint32_t, Degree<1024>>(
        v_stream, (uint32_t *)lwe_array_out, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 2048:
    host_bootstrap_amortized<uint32_t, Degree<2048>>(
        v_stream, (uint32_t *)lwe_array_out, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 4096:
    host_bootstrap_amortized<uint32_t, Degree<4096>>(
        v_stream, (uint32_t *)lwe_array_out, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 8192:
    host_bootstrap_amortized<uint32_t, Degree<8192>>(
        v_stream, (uint32_t *)lwe_array_out, (uint32_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint32_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  default:
    break;
  }
}

void cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
    void *v_stream, void *lwe_array_out, void *lut_vector,
    void *lut_vector_indexes, void *lwe_array_in, void *bootstrapping_key,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t num_lut_vectors, uint32_t lwe_idx, uint32_t max_shared_memory) {

  assert(
      ("Error (GPU amortized PBS): base log should be <= 8", base_log <= 8));
  assert(("Error (GPU amortized PBS): glwe_dimension should be equal to 1",
          glwe_dimension == 1));
  assert(("Error (GPU amortized PBS): polynomial size should be one of 512, "
          "1024, 2048, 4096, 8192",
          polynomial_size == 512 || polynomial_size == 1024 ||
              polynomial_size == 2048 || polynomial_size == 4096 ||
              polynomial_size == 8192));

  switch (polynomial_size) {
  case 512:
    host_bootstrap_amortized<uint64_t, Degree<512>>(
        v_stream, (uint64_t *)lwe_array_out, (uint64_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 1024:
    host_bootstrap_amortized<uint64_t, Degree<1024>>(
        v_stream, (uint64_t *)lwe_array_out, (uint64_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 2048:
    host_bootstrap_amortized<uint64_t, Degree<2048>>(
        v_stream, (uint64_t *)lwe_array_out, (uint64_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 4096:
    host_bootstrap_amortized<uint64_t, Degree<4096>>(
        v_stream, (uint64_t *)lwe_array_out, (uint64_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  case 8192:
    host_bootstrap_amortized<uint64_t, Degree<8192>>(
        v_stream, (uint64_t *)lwe_array_out, (uint64_t *)lut_vector,
        (uint32_t *)lut_vector_indexes, (uint64_t *)lwe_array_in,
        (double2 *)bootstrapping_key, lwe_dimension, polynomial_size, base_log,
        level_count, num_samples, num_lut_vectors, lwe_idx, max_shared_memory);
    break;
  default:
    break;
  }
}
