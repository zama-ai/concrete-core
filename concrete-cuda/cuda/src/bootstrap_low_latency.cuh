#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#include <helper_cuda.h>
#endif

#ifndef LOWLAT_PBS_H
#define LOWLAT_PBS_H

#include "cooperative_groups.h"

#include "../include/helper_cuda.h"
#include "bootstrap.h"
#include "complex/operations.cuh"
#include "crypto/gadget.cuh"
#include "crypto/torus.cuh"
#include "fft/bnsmfft.cuh"
#include "fft/smfft.cuh"
#include "fft/twiddles.cuh"
#include "polynomial/parameters.cuh"
#include "polynomial/polynomial.cuh"
#include "polynomial/polynomial_math.cuh"
#include "utils/memory.cuh"
#include "utils/timer.cuh"

// Cooperative groups are used in the low latency
// version of the bootstrapping
using namespace cooperative_groups;
namespace cg = cooperative_groups;

template <typename Torus, class params>
__device__ void
mul_trgsw_trlwe(Torus *accumulator,
                double2 *fft,
                int16_t *trlwe_decomposed,
                double2 *mask_join_buffer,
                double2 *body_join_buffer,
                double2 *bootstrapping_key,
                int polynomial_size, int l_gadget, int iteration, grid_group &grid) {

  // Put the decomposed TRLWE sample in the Fourier domain
  real_to_complex_compressed<int16_t, params>(trlwe_decomposed,
                                              fft);
  synchronize_threads_in_block();

  // Switch to the FFT space
  NSMFFT_direct<HalfDegree<params>>(fft);
  synchronize_threads_in_block();

  correction_direct_fft_inplace<params>(fft);
  synchronize_threads_in_block();



  // Get the pieces of the bootstrapping key that will be needed for the
  // external product; blockIdx.x is the ID of the block that's executing
  // this function, so we end up getting the lines of the bootstrapping key
  // needed to perform the external product in this block (corresponding to
  // the same decomposition level)

//  auto bsk_mask_slice = bootstrapping_key.get_ith_mask_kth_block(
//      gpu_num, iteration, blockIdx.y, blockIdx.x);
//  auto bsk_body_slice = bootstrapping_key.get_ith_body_kth_block(
//      gpu_num, iteration, blockIdx.y, blockIdx.x);

    auto bsk_mask_slice = PolynomialFourier<double2, params>(
      get_ith_mask_kth_block(
          bootstrapping_key, iteration, blockIdx.y, blockIdx.x,
          polynomial_size, 1, l_gadget));
    auto bsk_body_slice = PolynomialFourier<double2, params>(
      get_ith_body_kth_block(
          bootstrapping_key, iteration, blockIdx.y, blockIdx.x,
          polynomial_size, 1, l_gadget));

  // Perform the matrix multiplication between the RGSW and the TRLWE,
  // each block operating on a single level for mask and body

  auto first_processed_bsk = (blockIdx.y == 0) ? bsk_mask_slice : bsk_body_slice;
  auto second_processed_bsk = (blockIdx.y == 0) ? bsk_body_slice : bsk_mask_slice;

  auto first_processed_acc = (blockIdx.y == 0) ? mask_join_buffer : body_join_buffer;
  auto second_processed_acc = (blockIdx.y == 0) ? body_join_buffer : mask_join_buffer;

  int tid = 0;

  //first product
  for(int i = 0; i < params::opt / 2; i++) {
      first_processed_acc[tid] = fft[tid] * first_processed_bsk.m_values[tid];
      tid += params::degree / params::opt;
  }

  grid.sync();
  tid = 0;
  //second product
    for(int i = 0; i < params::opt / 2; i++) {
        second_processed_acc[tid] += fft[tid] * second_processed_bsk.m_values[tid];
        tid += params::degree / params::opt;
    }


  // -----------------------------------------------------------------

  // All blocks are synchronized here; after this sync, *_join_buffer has the
  // values needed from every other block
  grid.sync();

  auto src_acc =  (blockIdx.y == 0) ? mask_join_buffer : body_join_buffer;

  // copy first product into fft buffer
  tid = 0;
  for (int i = 0; i < params::opt / 2; i++) {
      fft[tid] = src_acc[tid];
      tid += params::degree / params::opt;
  }
  synchronize_threads_in_block();

  // accumulate rest of the products into fft buffer
  for (int l = 1; l < gridDim.x; l++) {
      auto cur_src_acc = &src_acc[l * params::degree / 2];
      tid = 0;
      for (int i = 0; i < params::opt / 2; i++) {
          fft[tid] = cur_src_acc[tid];
          tid += params::degree / params::opt;
      }
  }

  synchronize_threads_in_block();

  correction_inverse_fft_inplace<params>(fft);
  synchronize_threads_in_block();

  // Perform the inverse FFT on the result of the RGSWxTRLWE and add to the
  // accumulator
  NSMFFT_inverse<HalfDegree<params>>(fft);
  synchronize_threads_in_block();

  add_to_torus<Torus, params>(fft, accumulator);

}

template <typename Torus, class params>
/*
 * Kernel launched by the low latency version of the
 * bootstrapping, that uses cooperative groups
 * lwe_out vector of output lwe s, with length (polynomial_size+1)*num_samples
 * lut_vector - vector of look up tables with length  polynomial_size * num_samples
 * lut_vector_indexes - mapping between lwe_in and lut_vector
 * lwe_in - vector of lwe inputs with length (lwe_mask_size + 1) * num_samples
 *
 */
__global__ void device_bootstrap_low_latency(
    Torus *lwe_out,
    Torus *lut_vector,
    Torus *lwe_in,
    double2 *bootstrapping_key,
    double2 *mask_join_buffer,
    double2 *body_join_buffer,
    uint32_t lwe_mask_size,
    uint32_t polynomial_size, uint32_t base_log, uint32_t l_gadget
    ) {

  grid_group grid = this_grid();
  
  // We use shared memory for the polynomials that are used often during the
  // bootstrap, since shared memory is kept in L1 cache and accessing it is
  // much faster than global memory
  extern __shared__ char sharedmem[];

  char* selected_memory = sharedmem;

  int16_t *accumulator_decomposed = (int16_t *)selected_memory;
  Torus *accumulator = (Torus*)accumulator_decomposed +
          polynomial_size / (sizeof(Torus) / sizeof(int16_t));
  double2 *accumulator_fft = (double2*)accumulator +
          polynomial_size / (sizeof(double2) / sizeof(Torus));

  // Reuse memory from accumulator_fft for accumulator_rotated
  Torus* accumulator_rotated = (Torus*)accumulator_fft;

  // The third dimension of the block is used to determine on which ciphertext
  // this block is operating, in the case of batch bootstraps
  auto block_lwe_in = &lwe_in[blockIdx.z * (lwe_mask_size + 1)];

  auto block_lut_vector =
          &lut_vector[blockIdx.z * params::degree * 2];

  auto block_mask_join_buffer = &mask_join_buffer[blockIdx.z * l_gadget * params::degree / 2];
  auto block_body_join_buffer = &body_join_buffer[blockIdx.z * l_gadget * params::degree / 2];

  // Since the space is L1 cache is small, we use the same memory location for
  // the rotated accumulator and the fft accumulator, since we know that the
  // rotated array is not in use anymore by the time we perform the fft

  GadgetMatrix<Torus, params> gadget(base_log, l_gadget);

  // Put "b" in [0, 2N[
  Torus b_hat = rescale_torus_element(
      block_lwe_in[lwe_mask_size],
      2 * params::degree);

  if (blockIdx.y == 0) {
      divide_by_monomial_negacyclic_inplace<Torus, params::opt,
              params::degree / params::opt>(
              accumulator, block_lut_vector, b_hat, true);
  }
  else {
      divide_by_monomial_negacyclic_inplace<Torus, params::opt,
              params::degree / params::opt>(
              accumulator, &block_lut_vector[params::degree], b_hat, false);
  }

  for (int i = 0; i < lwe_mask_size; i++) {
    synchronize_threads_in_block();

    // Put "a" in [0, 2N[
    Torus a_hat = rescale_torus_element(
        block_lwe_in[i],
        2 * params::degree); // 2 * params::log2_degree + 1);

    if (a_hat == 0) {
      // todo(Joao): **cannot use this optimization**
      // the reason is that one of the input ciphertexts (blockIdx.z)
      // might skip an iteration while others don't, which as a result
      // will make that block not call the grid.sync(), causing a deadlock;
      // maybe it's a workaround to add grid.sync() here, but not sure if
      // there are any edge cases?

      // continue
    }

    // Perform ACC * (X^ä - 1)
    multiply_by_monomial_negacyclic_and_sub_polynomial<
          Torus, params::opt, params::degree / params::opt>(
          accumulator, accumulator_rotated, a_hat);


    // Perform a rounding to increase the accuracy of the
    // bootstrapped ciphertext
    round_to_closest_multiple_inplace<Torus, params::opt,
          params::degree / params::opt>(
          accumulator_rotated, base_log, l_gadget);



    // Decompose the accumulator. Each block gets one level of the
    // decomposition, for the mask and the body (so block 0 will have the
    // accumulator decomposed at level 0, 1 at 1, etc.)
    gadget.decompose_one_level(accumulator_decomposed, accumulator_rotated,
                               blockIdx.x);

    // We are using the same memory space for accumulator_fft and
    // accumulator_rotated, so we need to synchronize here to make sure they
    // don't modify the same memory space at the same time
    synchronize_threads_in_block();
    // Perform G^-1(ACC) * RGSW -> TRLWE
    mul_trgsw_trlwe<Torus, params>(
        accumulator,
        accumulator_fft,
        accumulator_decomposed,
        block_mask_join_buffer,
        block_body_join_buffer,
        bootstrapping_key,
        polynomial_size, l_gadget, i, grid);
  }
    
  auto block_lwe_out = &lwe_out[blockIdx.z * (polynomial_size + 1)];

  if (blockIdx.x == 0 && blockIdx.y == 0) {
    // Perform a sample extract. At this point, all blocks have the result, but
    // we do the computation at block 0 to avoid waiting for extra blocks, in
    // case they're not synchronized
    sample_extract_mask<Torus, params>(block_lwe_out, accumulator);
  } else if (blockIdx.x == 0 && blockIdx.y == 1) {
    sample_extract_body<Torus, params>(block_lwe_out, accumulator);
  }
  
}


/*
 * Host wrapper to the low latency version
 * of bootstrapping
 */
template <typename Torus, class params>
__host__ void host_bootstrap_low_latency(
    void *v_stream,
    Torus *lwe_out,
    Torus *lut_vector,
    uint32_t *lut_vector_indexes,
    Torus *lwe_in,
    double2 *bootstrapping_key,
    uint32_t lwe_mask_size,
    uint32_t polynomial_size,
    uint32_t base_log,
    uint32_t l_gadget,
    uint32_t num_samples,
    uint32_t num_lut_vectors) {
  auto stream = static_cast<cudaStream_t *>(v_stream);

  int buffer_size_per_gpu = l_gadget * num_samples * polynomial_size / 2 * sizeof(double2);
  double2 *mask_buffer_fft;
  double2 *body_buffer_fft;
  checkCudaErrors(cudaMalloc((void **)&mask_buffer_fft, buffer_size_per_gpu));
  checkCudaErrors(cudaMalloc((void **)&body_buffer_fft, buffer_size_per_gpu));


  int bytes_needed =
      sizeof(int16_t) * polynomial_size +   // accumulator_decomp
      sizeof(Torus) * polynomial_size +   // accumulator
      sizeof(double2) * polynomial_size / 2;  // accumulator fft

  int thds = polynomial_size / params::opt;
  dim3 grid(l_gadget, 2, num_samples);

  void *kernel_args[10];
  kernel_args[0] = &lwe_out;
  kernel_args[1] = &lut_vector;
  kernel_args[2] = &lwe_in;
  kernel_args[3] = &bootstrapping_key;
  kernel_args[4] = &mask_buffer_fft;
  kernel_args[5] = &body_buffer_fft;
  kernel_args[6] = &lwe_mask_size;
  kernel_args[7] = &polynomial_size;
  kernel_args[8] = &base_log;
  kernel_args[9] =&l_gadget;

  checkCudaErrors(cudaFuncSetAttribute(device_bootstrap_low_latency<Torus,
                                                                    params>,
                           cudaFuncAttributeMaxDynamicSharedMemorySize,
                           bytes_needed));
  cudaFuncSetCacheConfig(device_bootstrap_low_latency<Torus, params>,
                             cudaFuncCachePreferShared);
  
  checkCudaErrors(cudaLaunchCooperativeKernel ( (void *)device_bootstrap_low_latency<Torus, params>, grid, thds,  (void**)kernel_args, bytes_needed, *stream )) ;     
  
  // Synchronize the streams before copying the result to lwe_out at the right
  // place
  cudaStreamSynchronize(*stream);
  cudaFree(mask_buffer_fft);
  cudaFree(body_buffer_fft);
}

#endif // LOWLAT_PBS_H
