use crate::backends::cuda::private::device::{CudaStream, GpuIndex};
use crate::prelude::sealed::AbstractEngineSeal;
use crate::prelude::AbstractEngine;
use concrete_cuda::cuda_bind::cuda_get_number_of_gpus;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum CudaError {
    DeviceNotFound,
    SharedMemoryNotFound(GpuIndex),
    NotEnoughDeviceMemory(GpuIndex),
    InvalidDeviceIndex(GpuIndex),
    UnspecifiedDeviceError(GpuIndex),
    PolynomialSizeNotSupported,
}
impl Display for CudaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CudaError::DeviceNotFound => {
                write!(f, "No GPU detected on the machine.")
            }
            CudaError::SharedMemoryNotFound(gpu_index) => {
                write!(f, "No shared memory detected on the GPU #{}.", gpu_index.0)
            }
            CudaError::NotEnoughDeviceMemory(gpu_index) => {
                write!(
                    f,
                    "The GPU #{} does not have enough global memory to hold all the data.",
                    gpu_index.0
                )
            }
            CudaError::InvalidDeviceIndex(gpu_index) => {
                write!(
                    f,
                    "The specified GPU index, {}, does not exist.",
                    gpu_index.0
                )
            }
            CudaError::PolynomialSizeNotSupported => {
                write!(
                    f,
                    "The polynomial size should be a power of 2. Values stricly lower than \
                512, and strictly greater than 8192, are not supported."
                )
            }
            CudaError::UnspecifiedDeviceError(gpu_index) => {
                write!(f, "Unspecified device error on GPU #{}.", gpu_index.0)
            }
        }
    }
}
impl Error for CudaError {}

/// The main engine exposed by the cuda backend.
///
/// This engine handles single-GPU and multi-GPU computations for the user. It always associates
/// one Cuda stream to each available Nvidia GPU, and splits the input ciphertexts evenly over
/// the GPUs (the last GPU may be a bit more loaded if the number of GPUs does not divide the
/// number of input ciphertexts). This engine does not give control over the streams, nor the GPU
/// load balancing. In this way, we can overlap computations done on different GPUs, but not
/// computations done on a given GPU, which are executed in a sequence.
// A finer access to streams could allow for more overlapping of computations
// on a given device. We'll probably want to support it in the future, in an AdvancedCudaEngine
// for example.
#[derive(Debug, Clone)]
pub struct CudaEngine {
    streams: Vec<CudaStream>,
    max_shared_memory: usize,
}

impl AbstractEngineSeal for CudaEngine {}

impl AbstractEngine for CudaEngine {
    type EngineError = CudaError;

    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let number_of_gpus = unsafe { cuda_get_number_of_gpus() as usize };
        if number_of_gpus == 0 {
            Err(CudaError::DeviceNotFound)
        } else {
            let mut streams: Vec<CudaStream> = Vec::new();
            for gpu_index in 0..number_of_gpus as u32 {
                streams.push(CudaStream::new(GpuIndex(gpu_index))?);
            }
            let max_shared_memory = streams[0].get_max_shared_memory()?;

            Ok(CudaEngine {
                streams,
                max_shared_memory: max_shared_memory as usize,
            })
        }
    }
}

impl CudaEngine {
    /// Get the number of available GPUs from the engine
    pub fn get_number_of_gpus(&self) -> usize {
        self.streams.len()
    }
    /// Get the Cuda streams from the engine
    pub fn get_cuda_streams(&self) -> &Vec<CudaStream> {
        &self.streams
    }
    /// Get the size of the shared memory (on device 0)
    pub fn get_cuda_shared_memory(&self) -> usize {
        self.max_shared_memory
    }

    fn compute_number_of_samples_lwe_ciphertext_vector(
        &self,
        samples_per_gpu: usize,
        lwe_ciphertext_count: usize,
        gpu_index: usize,
    ) -> usize {
        let mut samples = samples_per_gpu;
        if gpu_index == self.get_number_of_gpus() - 1
            && lwe_ciphertext_count % self.get_number_of_gpus() as usize != 0
        {
            samples += lwe_ciphertext_count - samples_per_gpu * self.get_number_of_gpus() as usize;
        }
        samples
    }
}

/// A variant of CudaEngine exposed by the cuda backend.
///
/// This engine implements an amortized version of bootstrap on the GPU.
/// It is dedicated to the execution of bootstraps over larger amounts of
/// input ciphertexts than the CudaEngine's bootstrap implementation.
#[derive(Debug, Clone)]
pub struct AmortizedCudaEngine {
    streams: Vec<CudaStream>,
    max_shared_memory: usize,
}

impl AbstractEngineSeal for AmortizedCudaEngine {}

impl AbstractEngine for AmortizedCudaEngine {
    type EngineError = CudaError;

    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let number_of_gpus = unsafe { cuda_get_number_of_gpus() as usize };
        if number_of_gpus == 0 {
            Err(CudaError::DeviceNotFound)
        } else {
            let mut streams: Vec<CudaStream> = Vec::new();
            for gpu_index in 0..number_of_gpus as u32 {
                streams.push(CudaStream::new(GpuIndex(gpu_index))?);
            }
            let max_shared_memory = streams[0].get_max_shared_memory()?;

            Ok(AmortizedCudaEngine {
                streams,
                max_shared_memory: max_shared_memory as usize,
            })
        }
    }
}

impl AmortizedCudaEngine {
    /// Get the number of available GPUs from the engine
    pub fn get_number_of_gpus(&self) -> usize {
        self.streams.len()
    }
    /// Get the Cuda streams from the engine
    pub fn get_cuda_streams(&self) -> &Vec<CudaStream> {
        &self.streams
    }
    /// Get the size of the shared memory (on device 0)
    pub fn get_cuda_shared_memory(&self) -> usize {
        self.max_shared_memory
    }
}

macro_rules! check_poly_size {
    ($poly_size: ident) => {
        if $poly_size != 512
            && $poly_size != 1024
            && $poly_size != 2048
            && $poly_size != 4096
            && $poly_size != 8192
        {
            return Err(CudaError::PolynomialSizeNotSupported.into());
        }
    };
}

mod destruction;
mod glwe_ciphertext_conversion;
mod glwe_ciphertext_vector_conversion;
mod lwe_bootstrap_key_conversion;
mod lwe_ciphertext_conversion;
mod lwe_ciphertext_discarding_bootstrap;
mod lwe_ciphertext_discarding_keyswitch;
mod lwe_ciphertext_vector_conversion;
mod lwe_ciphertext_vector_discarding_bootstrap;
mod lwe_ciphertext_vector_discarding_keyswitch;
mod lwe_keyswitch_key_conversion;
