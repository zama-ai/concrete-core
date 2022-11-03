use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaLwePrivateFunctionalPackingKeyswitchKey32, CudaLwePrivateFunctionalPackingKeyswitchKey64,
};
use crate::backends::cuda::private::crypto::keyswitch::CudaLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{
    FunctionalPackingKeyswitchKeyCount, LwePrivateFunctionalPackingKeyswitchKey32,
    LwePrivateFunctionalPackingKeyswitchKey64,
};
use crate::specification::engines::{
    LwePrivateFunctionalPackingKeyswitchKeyConversionEngine,
    LwePrivateFunctionalPackingKeyswitchKeyConversionError,
};
use crate::specification::entities::LwePrivateFunctionalPackingKeyswitchKeyEntity;

impl From<CudaError> for LwePrivateFunctionalPackingKeyswitchKeyConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

impl
    LwePrivateFunctionalPackingKeyswitchKeyConversionEngine<
        LwePrivateFunctionalPackingKeyswitchKey32,
        CudaLwePrivateFunctionalPackingKeyswitchKey32,
    > for CudaEngine
{
    fn convert_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input: &LwePrivateFunctionalPackingKeyswitchKey32,
    ) -> Result<
        CudaLwePrivateFunctionalPackingKeyswitchKey32,
        LwePrivateFunctionalPackingKeyswitchKeyConversionError<CudaError>,
    > {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.decomposition_level_count().0
                * input.output_glwe_dimension().to_glwe_size().0
                * input.output_polynomial_size().0
                * input.input_lwe_dimension().to_lwe_size().0;

            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_private_functional_packing_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input: &LwePrivateFunctionalPackingKeyswitchKey32,
    ) -> CudaLwePrivateFunctionalPackingKeyswitchKey32 {
        // Copy the entire input vector over all GPUs
        let mut d_vecs = Vec::with_capacity(self.get_number_of_gpus().0);

        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0;
        for stream in self.streams.iter() {
            let mut d_vec = stream.malloc::<u32>(data_per_gpu as u32);
            stream.copy_to_gpu(&mut d_vec, input.0.as_tensor().as_slice());
            d_vecs.push(d_vec);
        }
        CudaLwePrivateFunctionalPackingKeyswitchKey32(
            CudaLwePrivateFunctionalPackingKeyswitchKeyList::<u32> {
                d_vecs,
                input_lwe_key_dimension: input.input_lwe_dimension(),
                output_glwe_key_dimension: input.output_glwe_dimension(),
                output_polynomial_size: input.output_polynomial_size(),
                decomposition_level_count: input.decomposition_level_count(),
                decomposition_base_log: input.decomposition_base_log(),
                fpksk_count: FunctionalPackingKeyswitchKeyCount(1),
            },
        )
    }
}

impl
    LwePrivateFunctionalPackingKeyswitchKeyConversionEngine<
        CudaLwePrivateFunctionalPackingKeyswitchKey32,
        LwePrivateFunctionalPackingKeyswitchKey32,
    > for CudaEngine
{
    fn convert_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input: &CudaLwePrivateFunctionalPackingKeyswitchKey32,
    ) -> Result<
        LwePrivateFunctionalPackingKeyswitchKey32,
        LwePrivateFunctionalPackingKeyswitchKeyConversionError<CudaError>,
    > {
        Ok(unsafe { self.convert_lwe_private_functional_packing_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input: &CudaLwePrivateFunctionalPackingKeyswitchKey32,
    ) -> LwePrivateFunctionalPackingKeyswitchKey32 {
        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u32; data_per_gpu];
        let stream = self.streams.first().unwrap();
        stream.copy_to_cpu::<u32>(&mut output, input.0.d_vecs.first().unwrap());

        LwePrivateFunctionalPackingKeyswitchKey32(
            LwePrivateFunctionalPackingKeyswitchKey::from_container(
                output,
                input.decomposition_base_log(),
                input.decomposition_level_count(),
                input.output_glwe_dimension(),
                input.output_polynomial_size(),
            ),
        )
    }
}

impl
    LwePrivateFunctionalPackingKeyswitchKeyConversionEngine<
        LwePrivateFunctionalPackingKeyswitchKey64,
        CudaLwePrivateFunctionalPackingKeyswitchKey64,
    > for CudaEngine
{
    fn convert_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input: &LwePrivateFunctionalPackingKeyswitchKey64,
    ) -> Result<
        CudaLwePrivateFunctionalPackingKeyswitchKey64,
        LwePrivateFunctionalPackingKeyswitchKeyConversionError<CudaError>,
    > {
        for stream in self.streams.iter() {
            let data_per_gpu = input.decomposition_level_count().0
                * input.output_glwe_dimension().to_glwe_size().0
                * input.output_polynomial_size().0
                * input.input_lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_private_functional_packing_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input: &LwePrivateFunctionalPackingKeyswitchKey64,
    ) -> CudaLwePrivateFunctionalPackingKeyswitchKey64 {
        // Copy the entire input vector over all GPUs
        let mut d_vecs = Vec::with_capacity(self.get_number_of_gpus().0);

        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0;
        for stream in self.streams.iter() {
            let mut d_vec = stream.malloc::<u64>(data_per_gpu as u32);
            stream.copy_to_gpu(&mut d_vec, input.0.as_tensor().as_slice());
            d_vecs.push(d_vec);
        }
        CudaLwePrivateFunctionalPackingKeyswitchKey64(
            CudaLwePrivateFunctionalPackingKeyswitchKeyList::<u64> {
                d_vecs,
                input_lwe_key_dimension: input.input_lwe_dimension(),
                output_glwe_key_dimension: input.output_glwe_dimension(),
                output_polynomial_size: input.output_polynomial_size(),
                decomposition_level_count: input.decomposition_level_count(),
                decomposition_base_log: input.decomposition_base_log(),
                fpksk_count: FunctionalPackingKeyswitchKeyCount(1),
            },
        )
    }
}

impl
    LwePrivateFunctionalPackingKeyswitchKeyConversionEngine<
        CudaLwePrivateFunctionalPackingKeyswitchKey64,
        LwePrivateFunctionalPackingKeyswitchKey64,
    > for CudaEngine
{
    fn convert_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input: &CudaLwePrivateFunctionalPackingKeyswitchKey64,
    ) -> Result<
        LwePrivateFunctionalPackingKeyswitchKey64,
        LwePrivateFunctionalPackingKeyswitchKeyConversionError<CudaError>,
    > {
        Ok(unsafe { self.convert_lwe_private_functional_packing_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input: &CudaLwePrivateFunctionalPackingKeyswitchKey64,
    ) -> LwePrivateFunctionalPackingKeyswitchKey64 {
        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u64; data_per_gpu];
        let stream = self.streams.first().unwrap();
        stream.copy_to_cpu::<u64>(&mut output, input.0.d_vecs.first().unwrap());

        LwePrivateFunctionalPackingKeyswitchKey64(
            LwePrivateFunctionalPackingKeyswitchKey::from_container(
                output,
                input.decomposition_base_log(),
                input.decomposition_level_count(),
                input.output_glwe_dimension(),
                input.output_polynomial_size(),
            ),
        )
    }
}
