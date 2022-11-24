#ifndef CONCRETE_CORE_GGSW_CUH
#define CONCRETE_CORE_GGSW_CUH

template <typename T, typename ST, class params, sharedMemDegree SMD>
__global__ void device_batch_fft_ggsw_vector(double2 *dest, T *src,
                                             char *device_mem) {

  extern __shared__ char sharedmem[];
  double2 *selected_memory;

  if constexpr (SMD == FULLSM)
    selected_memory = (double2 *)sharedmem;
  else
    selected_memory = (double2 *)device_mem[blockIdx.x * params::degree];

  // Compression
  int offset = blockIdx.x * blockDim.x;
  int tid = threadIdx.x;
  int log_2_opt = params::opt >> 1;

#pragma unroll
  for (int i = 0; i < log_2_opt; i++) {
    ST x = src[(2 * tid) + params::opt * offset];
    ST y = src[(2 * tid + 1) + params::opt * offset];
    selected_memory[tid].x = x / (double)std::numeric_limits<T>::max();
    selected_memory[tid].y = y / (double)std::numeric_limits<T>::max();
    tid += params::degree / params::opt;
  }
  synchronize_threads_in_block();

  // Switch to the FFT space
  NSMFFT_direct<HalfDegree<params>>(selected_memory);
  synchronize_threads_in_block();

  correction_direct_fft_inplace<params>(selected_memory);
  synchronize_threads_in_block();

  // Write the output to global memory
  tid = threadIdx.x;
#pragma unroll
  for (int j = 0; j < log_2_opt; j++) {
    dest[tid + (params::opt >> 1) * offset] = selected_memory[tid];
    tid += params::degree / params::opt;
  }
}

/**
 * Applies the FFT transform on sequence of GGSW ciphertexts already in the
 * global memory
 */
template <typename T, typename ST, class params>
void batch_fft_ggsw_vector(void *v_stream, double2 *dest, T *src, uint32_t r,
                           uint32_t glwe_dim, uint32_t polynomial_size,
                           uint32_t level_count, uint32_t gpu_index,
                           uint32_t max_shared_memory) {

  auto stream = static_cast<cudaStream_t *>(v_stream);

  int shared_memory_size = sizeof(double) * polynomial_size;

  int gridSize = r * (glwe_dim + 1) * (glwe_dim + 1) * level_count;
  int blockSize = polynomial_size / params::opt;

  char *d_mem;
  if (max_shared_memory < shared_memory_size) {
    d_mem = (char *)cuda_malloc_async(shared_memory_size, *stream, gpu_index);
    device_batch_fft_ggsw_vector<T, ST, params, NOSM>
        <<<gridSize, blockSize, 0, *stream>>>(dest, src, d_mem);
    checkCudaErrors(cudaGetLastError());
    cuda_drop_async(d_mem, *stream, gpu_index);
  } else {
    device_batch_fft_ggsw_vector<T, ST, params, FULLSM>
        <<<gridSize, blockSize, shared_memory_size, *stream>>>(dest, src,
                                                               d_mem);
    checkCudaErrors(cudaGetLastError());
  }
}

#endif // CONCRETE_CORE_GGSW_CUH
