use crate::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::{CudaLweCiphertext32, CudaLweCiphertext64};
use crate::backends::cuda::private::crypto::lwe::ciphertext::CudaLweCiphertext;
use crate::backends::cuda::private::pointers::CudaLweCiphertextPointer;
use crate::commons::crypto::lwe::LweCiphertext;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{LweCiphertextConversionEngine, LweCiphertextConversionError};
use crate::specification::entities::LweCiphertextEntity;

impl From<CudaError> for LweCiphertextConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext with 32 bits of precision from CPU to GPU 0.
impl LweCiphertextConversionEngine<LweCiphertext32, CudaLweCiphertext32> for CudaEngine {
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
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext)?;
    /// default_engine.destroy(h_ciphertext)?;
    /// cuda_engine.destroy(d_ciphertext);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext(
        &mut self,
        input: &LweCiphertext32,
    ) -> Result<CudaLweCiphertext32, LweCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.lwe_dimension().to_lwe_size().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_lwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_unchecked(
        &mut self,
        input: &LweCiphertext32,
    ) -> CudaLweCiphertext32 {
        let alloc_size = input.lwe_dimension().to_lwe_size().0 as u32;
        let input_slice = input.0.as_tensor().as_slice();
        let stream = &self.streams[0];
        let d_ptr = stream.malloc::<u32>(alloc_size);
        stream.copy_to_gpu::<u32>(d_ptr, input_slice);
        CudaLweCiphertext32(CudaLweCiphertext::<u32> {
            d_ptr: CudaLweCiphertextPointer(d_ptr),
            lwe_dimension: input.lwe_dimension(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext with 32 bits of precision from GPU 0 to CPU.
impl LweCiphertextConversionEngine<CudaLweCiphertext32, LweCiphertext32> for CudaEngine {
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
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// let h_ciphertext_output: LweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&d_ciphertext)?;
    /// assert_eq!(h_ciphertext_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(h_ciphertext, h_ciphertext_output);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext)?;
    /// default_engine.destroy(h_ciphertext)?;
    /// cuda_engine.destroy(d_ciphertext);
    /// default_engine.destroy(h_ciphertext_output)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext(
        &mut self,
        input: &CudaLweCiphertext32,
    ) -> Result<LweCiphertext32, LweCiphertextConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_unchecked(
        &mut self,
        input: &CudaLweCiphertext32,
    ) -> LweCiphertext32 {
        let mut output = vec![0_u32; input.lwe_dimension().to_lwe_size().0];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, input.0.get_ptr().0);

        LweCiphertext32(LweCiphertext::from_container(output))
    }
}

/// # Description
/// Convert an LWE ciphertext with 64 bits of precision from CPU to GPU 0.
impl LweCiphertextConversionEngine<LweCiphertext64, CudaLweCiphertext64> for CudaEngine {
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
    /// let input = 3_u64 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext)?;
    /// default_engine.destroy(h_ciphertext)?;
    /// cuda_engine.destroy(d_ciphertext);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext(
        &mut self,
        input: &LweCiphertext64,
    ) -> Result<CudaLweCiphertext64, LweCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.lwe_dimension().to_lwe_size().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_lwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_unchecked(
        &mut self,
        input: &LweCiphertext64,
    ) -> CudaLweCiphertext64 {
        let alloc_size = input.lwe_dimension().to_lwe_size().0 as u32;
        let input_slice = input.0.as_tensor().as_slice();
        let stream = &self.streams[0];
        let d_ptr = stream.malloc::<u64>(alloc_size);
        stream.copy_to_gpu::<u64>(d_ptr, input_slice);
        CudaLweCiphertext64(CudaLweCiphertext::<u64> {
            d_ptr: CudaLweCiphertextPointer(d_ptr),
            lwe_dimension: input.lwe_dimension(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext with 64 bits of precision from GPU 0 to CPU.
impl LweCiphertextConversionEngine<CudaLweCiphertext64, LweCiphertext64> for CudaEngine {
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
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// let h_ciphertext_output: LweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&d_ciphertext)?;
    /// assert_eq!(h_ciphertext_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(h_ciphertext, h_ciphertext_output);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext)?;
    /// default_engine.destroy(h_ciphertext)?;
    /// cuda_engine.destroy(d_ciphertext);
    /// default_engine.destroy(h_ciphertext_output)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext(
        &mut self,
        input: &CudaLweCiphertext64,
    ) -> Result<LweCiphertext64, LweCiphertextConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_unchecked(
        &mut self,
        input: &CudaLweCiphertext64,
    ) -> LweCiphertext64 {
        let mut output = vec![0_u64; input.lwe_dimension().to_lwe_size().0];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, input.0.get_ptr().0);

        LweCiphertext64(LweCiphertext::from_container(output))
    }
}
