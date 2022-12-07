use crate::backends::cuda::private::crypto::keyswitch::CudaLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{
    CudaEngine, CudaError, CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionEngine,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
};
use crate::specification::engines::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionError;

impl From<CudaError>
    for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionError<CudaError>
{
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionEngine<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    > for CudaEngine
{
    fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> Result<
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionError<CudaError>,
    > {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.decomposition_level_count().0
                * input.output_glwe_dimension().to_glwe_size().0
                * input.output_polynomial_size().0
                * input.input_lwe_dimension().to_lwe_size().0
                * input.key_count().0;

            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe {
            self.convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                input,
            )
        })
    }

    unsafe fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
        // Copy the entire input vector over all GPUs
        let mut d_vecs = Vec::with_capacity(self.get_number_of_gpus().0);

        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0
            * input.key_count().0;
        for stream in self.streams.iter() {
            let mut d_vec = stream.malloc::<u32>(data_per_gpu as u32);
            stream.copy_to_gpu(&mut d_vec, input.0.as_tensor().as_slice());
            d_vecs.push(d_vec);
        }
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
            CudaLwePrivateFunctionalPackingKeyswitchKeyList::<u32> {
                d_vecs,
                input_lwe_key_dimension: input.input_lwe_dimension(),
                output_glwe_key_dimension: input.output_glwe_dimension(),
                output_polynomial_size: input.output_polynomial_size(),
                decomposition_level_count: input.decomposition_level_count(),
                decomposition_base_log: input.decomposition_base_log(),
                fpksk_count: input.key_count(),
            },
        )
    }
}

impl
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionEngine<
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    > for CudaEngine
{
    fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> Result<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionError<CudaError>,
    > {
        Ok(unsafe {
            self.convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                input,
            )
        })
    }

    unsafe fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0
            * input.key_count().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u32; data_per_gpu];
        let stream = self.streams.first().unwrap();
        stream.copy_to_cpu::<u32>(&mut output, input.0.d_vecs.first().unwrap());

        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
            LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
                output,
                input.decomposition_base_log(),
                input.decomposition_level_count(),
                input.input_lwe_dimension(),
                input.output_glwe_dimension(),
                input.output_polynomial_size(),
                input.key_count(),
            ),
        )
    }
}

impl
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionEngine<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for CudaEngine
{
    fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Result<
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionError<CudaError>,
    > {
        for stream in self.streams.iter() {
            let data_per_gpu = input.decomposition_level_count().0
                * input.output_glwe_dimension().to_glwe_size().0
                * input.output_polynomial_size().0
                * input.input_lwe_dimension().to_lwe_size().0
                * input.key_count().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe {
            self.convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                input,
            )
        })
    }

    unsafe fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
        // Copy the entire input vector over all GPUs
        let mut d_vecs = Vec::with_capacity(self.get_number_of_gpus().0);

        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0
            * input.key_count().0;
        for stream in self.streams.iter() {
            let mut d_vec = stream.malloc::<u64>(data_per_gpu as u32);
            stream.copy_to_gpu(&mut d_vec, input.0.as_tensor().as_slice());
            d_vecs.push(d_vec);
        }
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
            CudaLwePrivateFunctionalPackingKeyswitchKeyList::<u64> {
                d_vecs,
                input_lwe_key_dimension: input.input_lwe_dimension(),
                output_glwe_key_dimension: input.output_glwe_dimension(),
                output_polynomial_size: input.output_polynomial_size(),
                decomposition_level_count: input.decomposition_level_count(),
                decomposition_base_log: input.decomposition_base_log(),
                fpksk_count: input.key_count(),
            },
        )
    }
}

impl
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionEngine<
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for CudaEngine
{
    fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Result<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysConversionError<CudaError>,
    > {
        Ok(unsafe {
            self.convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                input,
            )
        })
    }

    unsafe fn convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
        let data_per_gpu = input.decomposition_level_count().0
            * input.output_glwe_dimension().to_glwe_size().0
            * input.output_polynomial_size().0
            * input.input_lwe_dimension().to_lwe_size().0
            * input.key_count().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u64; data_per_gpu];
        let stream = self.streams.first().unwrap();
        stream.copy_to_cpu::<u64>(&mut output, input.0.d_vecs.first().unwrap());

        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
            LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
                output,
                input.decomposition_base_log(),
                input.decomposition_level_count(),
                input.input_lwe_dimension(),
                input.output_glwe_dimension(),
                input.output_polynomial_size(),
                input.key_count(),
            ),
        )
    }
}
