# concrete-cuda

## Introduction

This repository holds the code for GPU acceleration of Zama's variant of TFHE.
It implements CUDA/C++ functions to perform homomorphic operations on LWE ciphertexts.

In this first API, it provides functions to allocate memory on the GPU, to copy data back 
and forth between the CPU and the GPU, to create and destroy Cuda streams, etc.:
- `cuda_create_stream`, `cuda_destroy_stream`
- `cuda_malloc`, `cuda_check_valid_malloc`
- `cuda_memcpy_async_to_cpu`, `cuda_memcpy_async_to_gpu`
- `cuda_get_number_of_gpus`
- `cuda_synchronize_device`
The cryptographic operations it provides are:
- an amortized implementation of the TFHE programmable bootstrap: `cuda_bootstrap_amortized_lwe_ciphertext_vector_32` and `cuda_bootstrap_amortized_lwe_ciphertext_vector_64`
- a low latency implementation of the TFHE programmable bootstrap: `cuda_bootstrap_low latency_lwe_ciphertext_vector_32` and `cuda_bootstrap_low_latency_lwe_ciphertext_vector_64`
- the keyswitch: `cuda_keyswitch_lwe_ciphertext_vector_32` and `cuda_keyswitch_lwe_ciphertext_vector_64`

These C++/CUDA functions are available to the [Concrete-core](https://github.com/zama-ai/concrete-core) 
implementation via a dedicated Rust API, which is wrapped in the `backend_cuda` of 
`concrete-core`.

## Dependencies

**Disclaimer**: Compilation on Windows/Mac is not supported yet. Only Nvidia GPUs are supported. 

- nvidia driver - for example, if you're running Ubuntu 20.04 check this [page](https://linuxconfig.org/how-to-install-the-nvidia-drivers-on-ubuntu-20-04-focal-fossa-linux) for installation
- [nvcc](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html) >= 10.0
- [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
- [cmake](https://cmake.org/) >= 3.8

## Build

The `concrete-cuda` functions are available in `concrete-core` via the `backend_cuda`.
To compile `concrete-core` with the Cuda backend, install the aforementioned dependencies, then in 
`concrete-core` type: 
```
cargo build --release --features=backend_cuda
```

### Standalone Cuda files compilation
The Cuda project held in `concrete-cuda` can be compiled separately from the Rust project in the 
following way:
```
git clone git@github.com:zama-ai/concrete-core
cd concrete-core/concrete-cuda/cuda
mkdir build
cd build
cmake ..
make
```
The compute capability is detected automatically (with the first GPU information) and set accordingly.
