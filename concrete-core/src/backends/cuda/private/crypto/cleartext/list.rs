use crate::backends::cuda::private::device::{CudaStream, GpuIndex, NumberOfGpus};
use crate::backends::cuda::private::vec::CudaVec;
use crate::backends::cuda::private::{compute_number_of_samples_on_gpu, number_of_active_gpus};
use crate::commons::crypto::encoding::CleartextList;
use crate::commons::math::tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::numeric::UnsignedInteger;
use crate::prelude::{CiphertextCount, CleartextCount};

#[derive(Debug)]
pub(crate) struct CudaCleartextList<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec per GPU
    pub(crate) d_vecs: Vec<CudaVec<T>>,
    // Number of cleartexts in the array
    pub(crate) cleartext_count: CleartextCount,
}

pub(crate) unsafe fn copy_cleartext_vector_from_cpu_to_gpu<T: UnsignedInteger, Cont>(
    streams: &[CudaStream],
    input: &CleartextList<Cont>,
    number_of_available_gpus: NumberOfGpus,
) -> Vec<CudaVec<T>>
where
    Cont: AsRefSlice<Element = T>,
{
    let input_slice = input.as_tensor().as_slice();
    let count = CiphertextCount(input.count().0);
    // In case there are less inputs than GPUs, we use just one GPU per input
    let number_of_gpus = number_of_active_gpus(number_of_available_gpus, count);
    let mut vecs = Vec::with_capacity(number_of_gpus.0);
    let samples_on_gpu_0 = compute_number_of_samples_on_gpu(number_of_gpus, count, GpuIndex(0)).0;
    for (gpu_index, chunk) in input_slice.chunks_exact(samples_on_gpu_0).enumerate() {
        let stream = &streams[gpu_index];
        if gpu_index == number_of_gpus.0 - 1 {
            let chunk_and_remainder = [
                chunk,
                input_slice.chunks_exact(samples_on_gpu_0).remainder(),
            ]
            .concat();
            let alloc_size = chunk_and_remainder.len();
            let mut d_vec = stream.malloc::<T>(alloc_size as u32);
            stream.copy_to_gpu::<T>(&mut d_vec, chunk_and_remainder.as_slice());
            vecs.push(d_vec);
        } else {
            let alloc_size = chunk.len();
            let mut d_vec = stream.malloc::<T>(alloc_size as u32);
            stream.copy_to_gpu::<T>(&mut d_vec, chunk);
            vecs.push(d_vec);
        }
    }
    vecs
}

pub(crate) unsafe fn copy_cleartext_vector_from_gpu_to_cpu<T: UnsignedInteger>(
    streams: &[CudaStream],
    input: &CudaCleartextList<T>,
    number_of_available_gpus: NumberOfGpus,
) -> Vec<T> {
    let data_per_gpu = compute_number_of_samples_on_gpu(
        number_of_available_gpus,
        CiphertextCount(input.cleartext_count.0),
        GpuIndex(0),
    )
    .0;

    let mut output = vec![T::ZERO; input.cleartext_count.0];
    for (gpu_index, chunks) in output.chunks_exact_mut(data_per_gpu).enumerate() {
        let stream = &streams[gpu_index];
        stream.copy_to_cpu::<T>(chunks, input.d_vecs.get(gpu_index).unwrap());
    }
    if data_per_gpu * number_of_available_gpus.0 < input.cleartext_count.0 {
        let last_chunk = output.chunks_exact_mut(data_per_gpu).into_remainder();
        let last_stream = streams.last().unwrap();
        last_stream.copy_to_cpu::<T>(last_chunk, input.d_vecs.last().unwrap());
    }
    output
}

#[allow(dead_code)]
pub(crate) unsafe fn discard_copy_cleartext_vector_from_gpu_to_cpu<T: UnsignedInteger>(
    output: &mut CleartextList<&mut [T]>,
    streams: &[CudaStream],
    input: &CudaCleartextList<T>,
    number_of_available_gpus: NumberOfGpus,
) {
    let data_per_gpu = compute_number_of_samples_on_gpu(
        number_of_available_gpus,
        CiphertextCount(input.cleartext_count.0),
        GpuIndex(0),
    )
    .0;

    for (gpu_index, chunks) in output
        .as_mut_tensor()
        .as_mut_slice()
        .chunks_exact_mut(data_per_gpu)
        .enumerate()
    {
        let stream = &streams[gpu_index];
        stream.copy_to_cpu::<T>(chunks, input.d_vecs.get(gpu_index).unwrap());
    }
    if data_per_gpu * number_of_available_gpus.0 < input.cleartext_count.0 {
        let last_chunk = output
            .as_mut_tensor()
            .as_mut_slice()
            .chunks_exact_mut(data_per_gpu)
            .into_remainder();
        let last_stream = streams.last().unwrap();
        last_stream.copy_to_cpu::<T>(last_chunk, input.d_vecs.last().unwrap());
    }
}
