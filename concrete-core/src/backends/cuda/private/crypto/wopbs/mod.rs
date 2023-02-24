use crate::backends::cuda::private::crypto::bootstrap::CudaBootstrapKey;
use crate::backends::cuda::private::crypto::keyswitch::CudaLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::backends::cuda::private::crypto::plaintext::list::CudaPlaintextList;
use crate::backends::cuda::private::device::CudaStream;
use crate::backends::cuda::private::vec::CudaVec;
use crate::commons::numeric::UnsignedInteger;
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount, GlweDimension,
    LweCiphertextCount, LweDimension, PolynomialSize, SharedMemoryAmount,
};

#[cfg(test)]
mod test;

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn execute_circuit_bootstrap_vertical_packing_on_gpu<T: UnsignedInteger>(
    streams: &[CudaStream],
    lwe_array_out: &mut CudaLweList<T>,
    lwe_array_in: &CudaLweList<T>,
    lut_vector: &CudaPlaintextList<T>,
    bsk: &CudaBootstrapKey<T>,
    cbs_fpksk: &CudaLwePrivateFunctionalPackingKeyswitchKeyList<T>,
    level_count_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    cuda_shared_memory: SharedMemoryAmount,
) {
    let stream = &streams[0];
    let lut_number = lwe_array_out.lwe_ciphertext_count.0;
    stream.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector::<T>(
        lwe_array_out.d_vecs.get_mut(0).unwrap(),
        lwe_array_in.d_vecs.get(0).unwrap(),
        lut_vector.d_vecs.get(0).unwrap(),
        bsk.d_vecs.get(0).unwrap(),
        cbs_fpksk.d_vecs.get(0).unwrap(),
        bsk.glwe_dimension,
        lwe_array_in.lwe_dimension,
        bsk.polynomial_size,
        bsk.decomp_level,
        bsk.decomp_base_log,
        cbs_fpksk.decomposition_level_count,
        cbs_fpksk.decomposition_base_log,
        level_count_cbs,
        base_log_cbs,
        lwe_array_in.lwe_ciphertext_count,
        lut_number,
        cuda_shared_memory,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn execute_lwe_ciphertext_vector_extract_bits_on_gpu<T: UnsignedInteger>(
    streams: &[CudaStream],
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    keyswitch_key: &CudaVec<T>,
    fourier_bsk: &CudaVec<f64>,
    number_of_bits: ExtractedBitsCount,
    delta_log: DeltaLog,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log_bsk: DecompositionBaseLog,
    level_count_bsk: DecompositionLevelCount,
    base_log_ksk: DecompositionBaseLog,
    level_count_ksk: DecompositionLevelCount,
    num_samples: LweCiphertextCount,
    cuda_shared_memory: SharedMemoryAmount,
) {
    let stream = &streams[0];

    stream.discard_extract_bits_lwe_ciphertext_vector::<T>(
        lwe_array_out,
        lwe_array_in,
        keyswitch_key,
        fourier_bsk,
        number_of_bits,
        delta_log,
        input_lwe_dimension,
        output_lwe_dimension,
        glwe_dimension,
        polynomial_size,
        base_log_bsk,
        level_count_bsk,
        base_log_ksk,
        level_count_ksk,
        num_samples,
        cuda_shared_memory,
    );
}
