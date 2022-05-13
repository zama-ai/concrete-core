use crate::backends::core::private::crypto::lwe::LweList;
use crate::prelude::{
    CoreEngine, LweCiphertext64, LweCiphertextEntity, LweCiphertextVector64,
    LweCiphertextVectorFromContainerError,
};
use crate::specification::engines::LweCiphertextVectorFromContainerEngine;
use concrete_commons::parameters::CiphertextCount;

impl LweCiphertextVectorFromContainerEngine<LweCiphertext64, LweCiphertextVector64> for CoreEngine {
    fn create_vector_from_container(
        &mut self,
        input: &[LweCiphertext64],
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorFromContainerError<Self::EngineError>>
    {
        unsafe { Ok(self.create_vector_from_container_unchecked(input)) }
    }

    unsafe fn create_vector_from_container_unchecked(
        &mut self,
        input: &[LweCiphertext64],
    ) -> LweCiphertextVector64 {
        let lwe_size = input[0].lwe_dimension().to_lwe_size();
        let lwe_count = CiphertextCount(input.len());
        let mut list = LweList::allocate(0_u64, lwe_size, lwe_count);

        for (mut ct_out, ct_in) in list.ciphertext_iter_mut().zip(input.iter()) {
            let (out_body, mut out_mask) = ct_out.get_mut_body_and_mask();
            *out_body = *ct_in.0.get_body();

            for (mask_out_i, mask_in_i) in out_mask
                .mask_element_iter_mut()
                .zip(ct_in.0.get_mask().mask_element_iter())
            {
                *mask_out_i = *mask_in_i;
            }
        }

        LweCiphertextVector64(list)
    }
}
