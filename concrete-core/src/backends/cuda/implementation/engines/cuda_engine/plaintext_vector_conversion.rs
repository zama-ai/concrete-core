use crate::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::{
    CudaPlaintextVector32, CudaPlaintextVector64,
};
use crate::backends::cuda::private::crypto::plaintext::list::{
    copy_plaintext_vector_from_cpu_to_gpu, copy_plaintext_vector_from_gpu_to_cpu, CudaPlaintextList,
};
use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::{compute_number_of_samples_on_gpu, number_of_active_gpus};
use crate::commons::crypto::encoding::PlaintextList;
use crate::prelude::{CiphertextCount, PlaintextVector32, PlaintextVector64};
use crate::specification::engines::{
    PlaintextVectorConversionEngine, PlaintextVectorConversionError,
};
use crate::specification::entities::PlaintextVectorEntity;

impl From<CudaError> for PlaintextVectorConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

impl PlaintextVectorConversionEngine<PlaintextVector32, CudaPlaintextVector32> for CudaEngine {
    fn convert_plaintext_vector(
        &mut self,
        input: &PlaintextVector32,
    ) -> Result<CudaPlaintextVector32, PlaintextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.plaintext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.plaintext_count().0),
                GpuIndex(gpu_index),
            )
            .0;
            let size = samples as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_plaintext_vector_unchecked(input) })
    }

    unsafe fn convert_plaintext_vector_unchecked(
        &mut self,
        input: &PlaintextVector32,
    ) -> CudaPlaintextVector32 {
        let vecs = copy_plaintext_vector_from_cpu_to_gpu::<u32, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaPlaintextVector32(CudaPlaintextList::<u32> {
            d_vecs: vecs,
            plaintext_count: input.plaintext_count(),
        })
    }
}

impl PlaintextVectorConversionEngine<CudaPlaintextVector32, PlaintextVector32> for CudaEngine {
    fn convert_plaintext_vector(
        &mut self,
        input: &CudaPlaintextVector32,
    ) -> Result<PlaintextVector32, PlaintextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_plaintext_vector_unchecked(input) })
    }

    unsafe fn convert_plaintext_vector_unchecked(
        &mut self,
        input: &CudaPlaintextVector32,
    ) -> PlaintextVector32 {
        let output = copy_plaintext_vector_from_gpu_to_cpu::<u32>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        PlaintextVector32(PlaintextList::from_container(output))
    }
}

impl PlaintextVectorConversionEngine<PlaintextVector64, CudaPlaintextVector64> for CudaEngine {
    fn convert_plaintext_vector(
        &mut self,
        input: &PlaintextVector64,
    ) -> Result<CudaPlaintextVector64, PlaintextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.plaintext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.plaintext_count().0),
                GpuIndex(gpu_index),
            )
            .0;
            let size = samples as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_plaintext_vector_unchecked(input) })
    }

    unsafe fn convert_plaintext_vector_unchecked(
        &mut self,
        input: &PlaintextVector64,
    ) -> CudaPlaintextVector64 {
        let vecs = copy_plaintext_vector_from_cpu_to_gpu::<u64, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaPlaintextVector64(CudaPlaintextList::<u64> {
            d_vecs: vecs,
            plaintext_count: input.plaintext_count(),
        })
    }
}

impl PlaintextVectorConversionEngine<CudaPlaintextVector64, PlaintextVector64> for CudaEngine {
    fn convert_plaintext_vector(
        &mut self,
        input: &CudaPlaintextVector64,
    ) -> Result<PlaintextVector64, PlaintextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_plaintext_vector_unchecked(input) })
    }

    unsafe fn convert_plaintext_vector_unchecked(
        &mut self,
        input: &CudaPlaintextVector64,
    ) -> PlaintextVector64 {
        let output = copy_plaintext_vector_from_gpu_to_cpu::<u64>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        PlaintextVector64(PlaintextList::from_container(output))
    }
}
