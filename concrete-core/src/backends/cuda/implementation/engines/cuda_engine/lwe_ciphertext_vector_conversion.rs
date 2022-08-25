use crate::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::{
    CudaLweCiphertextVector32, CudaLweCiphertextVector64,
};
use crate::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::commons::crypto::lwe::LweList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{LweCiphertextVector32, LweCiphertextVector64};
use crate::specification::engines::{
    LweCiphertextVectorConversionEngine, LweCiphertextVectorConversionError,
};
use crate::specification::entities::LweCiphertextVectorEntity;

impl From<CudaError> for LweCiphertextVectorConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 32 bits of precision from CPU to GPU.
///
/// The input ciphertext vector is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextVectorConversionEngine<LweCiphertextVector32, CudaLweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector32,
    ) -> Result<CudaLweCiphertextVector32, LweCiphertextVectorConversionError<CudaError>> {
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        for (gpu_index, stream) in self.streams.iter().enumerate() {
            let samples = self.compute_number_of_samples_lwe_ciphertext_vector(
                samples_per_gpu,
                input.lwe_ciphertext_count().0,
                gpu_index,
            );
            let data_per_gpu = samples * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector32,
    ) -> CudaLweCiphertextVector32 {
        // Split the input vector over GPUs
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        let data_per_gpu = samples_per_gpu * input.lwe_dimension().to_lwe_size().0;
        let input_slice = input.0.as_tensor().as_slice();
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus() as usize);
        for (gpu_index, chunk) in input_slice.chunks_exact(data_per_gpu).enumerate() {
            let stream = &self.streams[gpu_index];
            let mut alloc_size = data_per_gpu as u32;
            if gpu_index == self.get_number_of_gpus() - 1 {
                alloc_size += input_slice.chunks_exact(data_per_gpu).remainder().len() as u32;
                let mut d_vec = stream.malloc::<u32>(alloc_size);
                let chunk_and_remainder =
                    [chunk, input_slice.chunks_exact(data_per_gpu).remainder()].concat();
                stream.copy_to_gpu::<u32>(&mut d_vec, chunk_and_remainder.as_slice());
                vecs.push(d_vec);
            } else {
                let mut d_vec = stream.malloc::<u32>(alloc_size);
                stream.copy_to_gpu::<u32>(&mut d_vec, chunk);
                vecs.push(d_vec);
            }
        }
        CudaLweCiphertextVector32(CudaLweList::<u32> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 32 bits of precision from GPU to CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVector32 on the CPU.
impl LweCiphertextVectorConversionEngine<CudaLweCiphertextVector32, LweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// let h_ciphertext_vector_output: LweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&d_ciphertext_vector)?;
    /// assert_eq!(h_ciphertext_vector_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     h_ciphertext_vector_output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// assert_eq!(h_ciphertext_vector, h_ciphertext_vector_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &CudaLweCiphertextVector32,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaLweCiphertextVector32,
    ) -> LweCiphertextVector32 {
        // Split the input vector over GPUs
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        let data_per_gpu = samples_per_gpu * input.lwe_dimension().to_lwe_size().0;

        let mut output =
            vec![0u32; input.lwe_dimension().to_lwe_size().0 * input.lwe_ciphertext_count().0];
        for (gpu_index, chunks) in output.chunks_exact_mut(data_per_gpu).enumerate() {
            let stream = &self.streams[gpu_index];
            stream.copy_to_cpu::<u32>(chunks, input.0.d_vecs.get(gpu_index).unwrap());
        }
        let last_chunk = output.chunks_exact_mut(data_per_gpu).into_remainder();
        let last_stream = &self.streams.last().unwrap();
        last_stream.copy_to_cpu::<u32>(last_chunk, input.0.d_vecs.last().unwrap());

        LweCiphertextVector32(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from CPU to GPU.
///
/// The input ciphertext vector is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextVectorConversionEngine<LweCiphertextVector64, CudaLweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> Result<CudaLweCiphertextVector64, LweCiphertextVectorConversionError<CudaError>> {
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let samples = self.compute_number_of_samples_lwe_ciphertext_vector(
                samples_per_gpu,
                input.lwe_ciphertext_count().0,
                gpu_index,
            );
            let data_per_gpu = samples * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> CudaLweCiphertextVector64 {
        // Split the input vector over GPUs
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        let data_per_gpu = samples_per_gpu * input.lwe_dimension().to_lwe_size().0;
        let input_slice = input.0.as_tensor().as_slice();
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus() as usize);
        for (gpu_index, chunk) in input_slice.chunks_exact(data_per_gpu).enumerate() {
            let stream = &self.streams[gpu_index];
            let mut alloc_size = data_per_gpu as u32;
            if gpu_index == self.get_number_of_gpus() - 1 {
                alloc_size += input_slice.chunks_exact(data_per_gpu).remainder().len() as u32;
                let mut d_vec = stream.malloc::<u64>(alloc_size);
                let chunk_and_remainder =
                    [chunk, input_slice.chunks_exact(data_per_gpu).remainder()].concat();
                stream.copy_to_gpu::<u64>(&mut d_vec, chunk_and_remainder.as_slice());
                vecs.push(d_vec);
            } else {
                let mut d_vec = stream.malloc::<u64>(alloc_size);
                stream.copy_to_gpu::<u64>(&mut d_vec, chunk);
                vecs.push(d_vec);
            }
        }
        CudaLweCiphertextVector64(CudaLweList::<u64> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from GPU to CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVector64 on the CPU.
impl LweCiphertextVectorConversionEngine<CudaLweCiphertextVector64, LweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// let h_ciphertext_vector_output: LweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&d_ciphertext_vector)?;
    /// assert_eq!(h_ciphertext_vector_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     h_ciphertext_vector_output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// assert_eq!(h_ciphertext_vector, h_ciphertext_vector_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &CudaLweCiphertextVector64,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaLweCiphertextVector64,
    ) -> LweCiphertextVector64 {
        // Split the input vector over GPUs
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        let data_per_gpu = samples_per_gpu * input.lwe_dimension().to_lwe_size().0;

        let mut output =
            vec![0u64; input.lwe_dimension().to_lwe_size().0 * input.lwe_ciphertext_count().0];
        for (gpu_index, chunks) in output.chunks_exact_mut(data_per_gpu).enumerate() {
            let stream = &self.streams[gpu_index];
            stream.copy_to_cpu::<u64>(chunks, input.0.d_vecs.get(gpu_index).unwrap());
        }
        let last_chunk = output.chunks_exact_mut(data_per_gpu).into_remainder();
        let stream = &self.streams[self.get_number_of_gpus() - 1];
        stream.copy_to_cpu::<u64>(last_chunk, input.0.d_vecs.last().unwrap());

        LweCiphertextVector64(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}
