use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::private::pointers::StreamPointer;
use concrete_commons::numeric::Numeric;
use concrete_cuda::cuda_bind::*;
use std::ffi::c_void;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuIndex(pub u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CudaStream {
    gpu_index: GpuIndex,
    stream: StreamPointer,
}

impl CudaStream {
    /// Creates a new stream attached to GPU at gpu_index
    pub(crate) fn new(gpu_index: GpuIndex) -> Result<Self, CudaError> {
        if gpu_index.0 >= unsafe { cuda_get_number_of_gpus() } as u32 {
            Err(CudaError::InvalidDeviceIndex(gpu_index))
        } else {
            let stream = StreamPointer(unsafe { cuda_create_stream(gpu_index.0) });
            Ok(CudaStream { gpu_index, stream })
        }
    }

    /// Gets the GPU index the stream is associated to
    pub(crate) fn gpu_index(&self) -> GpuIndex {
        self.gpu_index
    }

    /// Gets the stream handle
    pub(crate) fn stream_handle(&self) -> StreamPointer {
        self.stream
    }

    /// Check that the GPU has enough global memory
    pub(crate) fn check_device_memory(&self, size: u64) -> Result<(), CudaError> {
        let valid = unsafe { cuda_check_valid_malloc(size, self.gpu_index().0) };
        match valid {
            0 => Ok(()),
            -1 => Err(CudaError::NotEnoughDeviceMemory(self.gpu_index())),
            -2 => Err(CudaError::InvalidDeviceIndex(self.gpu_index())),
            _ => Err(CudaError::UnspecifiedDeviceError(self.gpu_index())),
        }
    }

    /// Allocates `elements` on the GPU
    pub(crate) fn malloc<T>(&self, elements: u32) -> *mut c_void
    where
        T: Numeric,
    {
        let size = elements as u64 * std::mem::size_of::<T>() as u64;
        unsafe { cuda_malloc(size, self.gpu_index().0) }
    }

    /// Copies data from slice into GPU pointer
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    /// - [CudaStream::cuda_synchronize_device] __must__ be called after the copy
    /// as soon as synchronization is required
    pub(crate) unsafe fn copy_to_gpu_async<T>(&self, dest: *mut c_void, src: &[T])
    where
        T: Numeric,
    {
        let size = (src.len() * std::mem::size_of::<T>()) as u64;
        cuda_memcpy_async_to_gpu(
            dest,
            src.as_ptr() as *const c_void,
            size,
            self.stream_handle().0,
            self.gpu_index().0,
        );
    }

    /// Copies data from slice into GPU pointer
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    pub(crate) unsafe fn copy_to_gpu<T>(&self, dest: *mut c_void, src: &[T])
    where
        T: Numeric,
    {
        self.copy_to_gpu_async(dest, src);
        self.synchronize_device();
    }

    /// Copies data from GPU pointer into slice
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    /// - [CudaStream::cuda_synchronize_device] __must__ be called as soon as synchronization is
    /// required
    pub(crate) unsafe fn copy_to_cpu_async<T>(&self, dest: &mut [T], src: *const c_void)
    where
        T: Numeric,
    {
        let size = (dest.len() * std::mem::size_of::<T>()) as u64;
        cuda_memcpy_async_to_cpu(
            dest.as_mut_ptr() as *mut c_void,
            src,
            size,
            self.stream_handle().0,
            self.gpu_index().0,
        );
    }

    /// Copies data from GPU pointer into slice
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    pub(crate) unsafe fn copy_to_cpu<T>(&self, dest: &mut [T], src: *const c_void)
    where
        T: Numeric,
    {
        self.copy_to_cpu_async(dest, src);
        self.synchronize_device();
    }

    /// Synchronizes the device
    #[allow(dead_code)]
    pub(crate) fn synchronize_device(&self) {
        unsafe { cuda_synchronize_device(self.gpu_index().0) };
    }

    /// Drop an array
    ///
    /// # Safety
    ///
    /// - `ptr` __must__ be a valid pointer
    pub(crate) unsafe fn drop(&self, ptr: *mut c_void) -> Result<(), CudaError> {
        let err = cuda_drop(ptr, self.gpu_index().0);
        match err {
            0 => Ok(()),
            -2 => Err(CudaError::InvalidDeviceIndex(self.gpu_index())),
            _ => Err(CudaError::UnspecifiedDeviceError(self.gpu_index())),
        }
    }

    /// Get the maximum amount of shared memory
    pub(crate) fn get_max_shared_memory(&self) -> Result<i32, CudaError> {
        let max_shared_memory = unsafe { cuda_get_max_shared_memory(self.gpu_index().0) };
        match max_shared_memory {
            0 => Err(CudaError::SharedMemoryNotFound(self.gpu_index())),
            -2 => Err(CudaError::InvalidDeviceIndex(self.gpu_index())),
            _ => Ok(max_shared_memory),
        }
    }

    /// Initialize twiddles
    #[allow(dead_code)]
    pub fn initialize_twiddles(&self, polynomial_size: u32) {
        unsafe { cuda_initialize_twiddles(polynomial_size, self.gpu_index.0) };
    }

    /// Convert bootstrap key
    #[allow(dead_code)]
    pub unsafe fn convert_lwe_bootstrap_key_32(
        &self,
        dest: *mut c_void,
        src: *mut c_void,
        input_lwe_dim: u32,
        glwe_dim: u32,
        l_gadget: u32,
        polynomial_size: u32,
    ) {
        cuda_convert_lwe_bootstrap_key_32(
            dest,
            src,
            self.stream.0,
            self.gpu_index.0,
            input_lwe_dim,
            glwe_dim,
            l_gadget,
            polynomial_size,
        )
    }

    /// Convert bootstrap key
    #[allow(dead_code)]
    pub unsafe fn convert_lwe_bootstrap_key_64(
        &self,
        dest: *mut c_void,
        src: *mut c_void,
        input_lwe_dim: u32,
        glwe_dim: u32,
        l_gadget: u32,
        polynomial_size: u32,
    ) {
        cuda_convert_lwe_bootstrap_key_64(
            dest,
            src,
            self.stream.0,
            self.gpu_index.0,
            input_lwe_dim,
            glwe_dim,
            l_gadget,
            polynomial_size,
        )
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_bootstrap_amortized_lwe_ciphertext_vector_32(
        &self,
        lwe_out: *mut c_void,
        test_vector: *const c_void,
        test_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    ) {
        cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
            self.stream.0,
            lwe_out,
            test_vector,
            test_vector_indexes,
            lwe_in,
            bootstrapping_key,
            lwe_dimension,
            polynomial_size,
            base_log,
            level,
            num_samples,
            num_samples,
            lwe_idx,
            max_shared_memory,
        )
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_bootstrap_amortized_lwe_ciphertext_vector_64(
        &self,
        lwe_out: *mut c_void,
        test_vector: *const c_void,
        test_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    ) {
        cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
            self.stream.0,
            lwe_out,
            test_vector,
            test_vector_indexes,
            lwe_in,
            bootstrapping_key,
            lwe_dimension,
            polynomial_size,
            base_log,
            level,
            num_samples,
            num_samples,
            lwe_idx,
            max_shared_memory,
        )
    }
    /// Discarding bootstrap on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_bootstrap_low_latency_lwe_ciphertext_vector_32(
        &self,
        lwe_out: *mut c_void,
        test_vector: *const c_void,
        test_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    ) {
        cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
            self.stream.0,
            lwe_out,
            test_vector,
            test_vector_indexes,
            lwe_in,
            bootstrapping_key,
            lwe_dimension,
            polynomial_size,
            base_log,
            level,
            num_samples,
            num_samples,
            lwe_idx,
            max_shared_memory,
        )
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_bootstrap_low_latency_lwe_ciphertext_vector_64(
        &self,
        lwe_out: *mut c_void,
        test_vector: *const c_void,
        test_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    ) {
        cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
            self.stream.0,
            lwe_out,
            test_vector,
            test_vector_indexes,
            lwe_in,
            bootstrapping_key,
            lwe_dimension,
            polynomial_size,
            base_log,
            level,
            num_samples,
            num_samples,
            lwe_idx,
            max_shared_memory,
        )
    }

    /// Discarding keyswitch on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_keyswitch_lwe_ciphertext_vector_32(
        &self,
        lwe_out: *mut c_void,
        lwe_in: *const c_void,
        input_lwe_dimension: u32,
        output_lwe_dimension: u32,
        keyswitch_key: *const c_void,
        base_log: u32,
        l_gadget: u32,
        num_samples: u32,
    ) {
        cuda_keyswitch_lwe_ciphertext_vector_32(
            self.stream.0,
            lwe_out,
            lwe_in,
            keyswitch_key,
            input_lwe_dimension,
            output_lwe_dimension,
            base_log,
            l_gadget,
            num_samples,
        )
    }

    /// Discarding keyswitch on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_keyswitch_lwe_ciphertext_vector_64(
        &self,
        lwe_out: *mut c_void,
        lwe_in: *const c_void,
        input_lwe_dimension: u32,
        output_lwe_dimension: u32,
        keyswitch_key: *const c_void,
        base_log: u32,
        l_gadget: u32,
        num_samples: u32,
    ) {
        cuda_keyswitch_lwe_ciphertext_vector_64(
            self.stream.0,
            lwe_out,
            lwe_in,
            keyswitch_key,
            input_lwe_dimension,
            output_lwe_dimension,
            base_log,
            l_gadget,
            num_samples,
        )
    }
}

impl Drop for CudaStream {
    fn drop(&mut self) {
        unsafe {
            cuda_destroy_stream(self.stream_handle().0, self.gpu_index().0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_gpu_info() {
        println!("Number of GPUs: {}", unsafe { cuda_get_number_of_gpus() });
        let gpu_index = GpuIndex(0);
        let stream = CudaStream::new(gpu_index).unwrap();
        println!(
            "Max shared memory: {}",
            stream.get_max_shared_memory().unwrap()
        )
    }
    #[test]
    fn allocate_and_copy() {
        let vec = vec![1_u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let gpu_index = GpuIndex(0);
        let stream = CudaStream::new(gpu_index).unwrap();
        stream.check_device_memory(vec.len() as u64).unwrap();
        let ptr = stream.malloc::<u64>(vec.len() as u32);
        unsafe {
            stream.copy_to_gpu(ptr, &vec);
        }
        let mut empty = vec![0_u64; vec.len()];
        unsafe {
            stream.copy_to_cpu(&mut empty, ptr);
        }
        assert_eq!(vec, empty);
        unsafe {
            stream.drop(ptr).unwrap();
        }
    }
}
