#[cfg(test)]
mod test;

use crate::backends::fftw::private::crypto::bootstrap::multivaluepbs::fourier_multiplication_torus_integer;
use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::math::fft::{AlignedVec, Complex64, Fft, FourierPolynomial};
use crate::commons::crypto::glwe::{GlweCiphertext, LwePackingKeyswitchKey};
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::{CastFrom, CastInto};
use crate::prelude::{MonomialDegree, PolynomialSize};

impl<Cont, Scalar> FourierBootstrapKey<Cont, Scalar>
where
    GlweCiphertext<Vec<Scalar>>: AsRefTensor<Element = Scalar>,
    Self: AsRefTensor<Element = Complex64>,
    Scalar: UnsignedTorus + CastInto<u64>,
    u64: CastFrom<Scalar>,
{
    /// Performs a bootstrap of a lwe ciphertext,
    /// with multiple given accumulators.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_commons::dispersion::LogStandardDev;
    /// use concrete_commons::numeric::CastInto;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    ///     PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::bootstrap::{
    ///     FourierBootstrapKey, FourierBuffers, StandardBootstrapKey,
    /// };
    /// use concrete_core::backends::core::private::crypto::encoding::Plaintext;
    /// use concrete_core::backends::core::private::crypto::glwe::GlweCiphertext;
    /// use concrete_core::backends::core::private::crypto::lwe::LweCiphertext;
    /// use concrete_core::backends::core::private::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use concrete_core::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use concrete_core::backends::core::private::math::fft::Complex64;
    /// use concrete_core::backends::core::private::math::tensor::AsMutTensor;
    ///
    /// // define settings
    /// let polynomial_size = PolynomialSize(1024);
    /// let rlwe_dimension = GlweDimension(1);
    /// let lwe_dimension = LweDimension(630);
    ///
    /// let level = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(7);
    /// let std = LogStandardDev::from_log_standard_dev(-29.);
    ///
    /// let mut secret_generator = SecretRandomGenerator::new(None);
    /// let mut encryption_generator = EncryptionRandomGenerator::new(None);
    ///
    /// let mut rlwe_sk =
    ///     GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    /// let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
    ///
    /// // allocation and generation of the key in coef domain:
    /// let mut coef_bsk = StandardBootstrapKey::allocate(
    ///     0 as u32,
    ///     rlwe_dimension.to_glwe_size(),
    ///     polynomial_size,
    ///     level,
    ///     base_log,
    ///     lwe_dimension,
    /// );
    /// coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);
    ///
    /// // allocation for the bootstrapping key
    /// let mut fourier_bsk = FourierBootstrapKey::allocate(
    ///     Complex64::new(0., 0.),
    ///     rlwe_dimension.to_glwe_size(),
    ///     polynomial_size,
    ///     level,
    ///     base_log,
    ///     lwe_dimension,
    /// );
    ///
    /// let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    /// fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);
    ///
    /// let message = Plaintext(2u32.pow(30));
    ///
    /// let mut lwe_in = LweCiphertext::allocate(0u32, lwe_dimension.to_lwe_size());
    /// let mut lwe_out_1 =
    ///     LweCiphertext::allocate(0u32, LweSize(rlwe_dimension.0 * polynomial_size.0 + 1));
    /// let mut lwe_out_2 =
    ///     LweCiphertext::allocate(0u32, LweSize(rlwe_dimension.0 * polynomial_size.0 + 1));
    /// lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);
    ///
    /// // accumulator is a trivial encryption of [0, 1/2N, 2/2N, ...]
    /// let mut accumulator =
    ///     GlweCiphertext::allocate(0u32, polynomial_size, rlwe_dimension.to_glwe_size());
    /// accumulator
    ///     .get_mut_body()
    ///     .as_mut_tensor()
    ///     .iter_mut()
    ///     .enumerate()
    ///     .for_each(|(i, a)| {
    ///         *a = (i as f64 * 2_f64.powi(32_i32 - 10 - 1)).cast_into();
    ///     });
    ///
    /// let vec_accumulator = vec![accumulator.clone(), accumulator];
    /// let mut vec_buffers = vec![buffers.clone(), buffers];
    /// let mut vec_lwe_out = vec![lwe_out_1, lwe_out_2];
    /// // bootstrap
    /// fourier_bsk.vector_bootstrap(
    ///     &mut vec_lwe_out,
    ///     &lwe_in,
    ///     &vec_accumulator,
    ///     &mut vec_buffers,
    /// );
    /// ```
    pub fn vector_bootstrap<C1, C2, C3>(
        &self,
        lwe_out: &mut [LweCiphertext<C1>],
        lwe_in: &LweCiphertext<C2>,
        accumulators: &[GlweCiphertext<C3>],
        buffer: &mut FourierBuffers<Scalar>,
    ) where
        LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        LweCiphertext<C2>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<C3>: AsRefTensor<Element = Scalar>,
    {
        for (ct_out, acc) in lwe_out.iter_mut().zip(accumulators.iter()) {
            self.bootstrap(ct_out, lwe_in, acc, buffer);
        }
    }

    pub fn treepbs<C1, C2, C3, C4>(
        &self,
        pks_key: &LwePackingKeyswitchKey<C1>,
        lwe_out: &mut LweCiphertext<C3>,
        vec_lwe_in: &[LweCiphertext<C3>],
        lwe_buffer_bootstrap: &mut [LweCiphertext<C4>],
        ksk: &LweKeyswitchKey<Vec<Scalar>>,
        accumulators: &mut [GlweCiphertext<C2>],
        buffers: &mut FourierBuffers<Scalar>,
        modulus: usize,
        index: usize,
        poly_redundancy: &Polynomial<Vec<Scalar>>,
    ) where
        LwePackingKeyswitchKey<C1>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<C2>: AsRefTensor<Element = Scalar>,
        LweCiphertext<C3>: AsMutTensor<Element = Scalar>,
        LweCiphertext<C4>: AsMutTensor<Element = Scalar>,
        C2: Clone + AsMutSlice<Element = Scalar>,
    {
        let base = modulus;
        self.treepbs_base(
            pks_key,
            lwe_out,
            vec_lwe_in,
            lwe_buffer_bootstrap,
            ksk,
            accumulators,
            buffers,
            modulus,
            base,
            index,
            poly_redundancy,
        )
    }

    pub fn treepbs_base<C1, C2, C3, C4>(
        &self,
        pks_key: &LwePackingKeyswitchKey<C1>,
        lwe_out: &mut LweCiphertext<C3>,
        vec_lwe_in: &[LweCiphertext<C3>],
        lwe_buffer_bootstrap: &mut [LweCiphertext<C4>],
        ksk: &LweKeyswitchKey<Vec<Scalar>>,
        accumulators: &mut [GlweCiphertext<C2>],
        buffers: &mut FourierBuffers<Scalar>,
        modulus: usize,
        base: usize,
        index: usize,
        poly_redundancy: &Polynomial<Vec<Scalar>>,
    ) where
        LwePackingKeyswitchKey<C1>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<C2>: AsRefTensor<Element = Scalar>,
        LweCiphertext<C3>: AsMutTensor<Element = Scalar>,
        LweCiphertext<C4>: AsMutTensor<Element = Scalar>,
        C2: Clone + AsMutSlice<Element = Scalar>,
    {
        let length = accumulators.len();

        if length == 1 {
            // We reached the end of the tree
            self.bootstrap(lwe_out, &vec_lwe_in[index], &accumulators[0], buffers);
            return;
        }

        //Evaluate every look up table with the ciphertext of index 'index'
        self.vector_bootstrap(
            lwe_buffer_bootstrap,
            &vec_lwe_in[index],
            &accumulators,
            buffers,
        );

        // Value of the shift the ciphertexts in the accumulator
        let box_size = accumulators[0].poly_size.0 / modulus;

        let nb_acc = length / base;

        for (acc_i, lwe_chunk) in accumulators[..nb_acc]
            .iter_mut()
            .zip(lwe_buffer_bootstrap.chunks_exact(base))
        {
            pks_key.create_accumulator_treepbs(
                acc_i,
                lwe_chunk,
                poly_redundancy, // Careful with poly redundancy
                box_size,
            );
        }

        self.treepbs_base(
            pks_key,
            lwe_out,
            vec_lwe_in,
            &mut lwe_buffer_bootstrap[..nb_acc],
            ksk,
            &mut accumulators[..nb_acc],
            buffers,
            modulus,
            base,
            index + 1,
            poly_redundancy,
        )
    }

    pub fn treepbs_with_multivalue<C1, C3>(
        &self,
        pks_key: &LwePackingKeyswitchKey<C3>,
        lwe_out: &mut LweCiphertext<C1>,
        vec_lwe_in: &[LweCiphertext<C1>],
        ksk: &LweKeyswitchKey<Vec<Scalar>>,
        buffers: &mut FourierBuffers<Scalar>,
        modulus: Scalar,
        index: usize,
        poly_redundancy: &Polynomial<Vec<Scalar>>,
        poly_acc: &[FourierPolynomial<AlignedVec<Complex64>>],
    ) where
        LwePackingKeyswitchKey<C3>: AsRefTensor<Element = Scalar>,
        LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        C1: Clone + AsRefSlice<Element = Scalar>,
    {
        let base = modulus;
        self.treepbs_with_multivalue_base(
            pks_key,
            lwe_out,
            vec_lwe_in,
            ksk,
            buffers,
            modulus,
            base,
            index,
            poly_redundancy,
            poly_acc,
        );
    }

    pub fn treepbs_with_multivalue_base<C1, C3>(
        &self,
        pks_key: &LwePackingKeyswitchKey<C3>,
        lwe_out: &mut LweCiphertext<C1>,
        vec_lwe_in: &[LweCiphertext<C1>],
        ksk: &LweKeyswitchKey<Vec<Scalar>>,
        buffers: &mut FourierBuffers<Scalar>,
        modulus: Scalar,
        base: Scalar,
        index: usize,
        poly_redundancy: &Polynomial<Vec<Scalar>>,
        poly_acc: &[FourierPolynomial<AlignedVec<Complex64>>],
    ) where
        LwePackingKeyswitchKey<C3>: AsRefTensor<Element = Scalar>,
        LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        C1: Clone + AsRefSlice<Element = Scalar>,
    {
        let length = poly_acc.len();

        // Evaluate the set of look up tables in clear
        let mut lwe_buffer_bootstrap: Vec<LweCiphertext<Vec<Scalar>>> = self
            .multivalue_programmable_bootstrap(
                &vec_lwe_in[0],
                modulus,
                poly_acc,
                buffers,
                // ksk,
            );

        // Value of the shift the ciphertexts in the accumulator
        let modulus_u64: u64 = modulus.cast_into();
        let base_u64: u64 = base.cast_into();
        let box_size = poly_acc[0].polynomial_size().0 / modulus_u64 as usize;

        // let nb_acc = length / modulus_u64 as usize;
        let nb_acc = length / base_u64 as usize;

        let mut accumulators = vec![
            GlweCiphertext::allocate(
                Scalar::ZERO,
                poly_acc[0].polynomial_size(),
                self.glwe_size(),
            );
            nb_acc
        ];

        for (acc_i, lwe_chunk) in accumulators
            .iter_mut()
            .zip(lwe_buffer_bootstrap.chunks_exact(base_u64 as usize))
        {
            pks_key.create_accumulator_treepbs::<Vec<Scalar>, _, Scalar>(
                acc_i,
                lwe_chunk,
                poly_redundancy,
                box_size,
            );
        }

        self.treepbs_base::<_, _, _, Vec<Scalar>>(
            pks_key,
            lwe_out,
            vec_lwe_in,
            &mut lwe_buffer_bootstrap[..nb_acc],
            ksk,
            &mut accumulators,
            buffers,
            modulus_u64 as usize,
            base_u64 as usize,
            index + 1,
            poly_redundancy,
        )
    }
}

// TODO should be moved into the proper module/file
impl<Scalar, Cont> LweKeyswitchKey<Cont>
where
    Scalar: UnsignedTorus,
    Self: AsRefTensor<Element = Scalar>,
{
    pub fn vector_keyswitch<C1, C2>(
        &self,
        lwe_slice_out: &mut [LweCiphertext<C1>],
        lwe_slice_in: &[LweCiphertext<C2>],
    ) where
        LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        LweCiphertext<C2>: AsRefTensor<Element = Scalar>,
    {
        for (ct_out, ct_in) in lwe_slice_out.iter_mut().zip(lwe_slice_in.iter()) {
            self.keyswitch_ciphertext(ct_out, ct_in);
        }
    }
}

pub fn generate_accumulator_treepbs<F>(
    f: F,
    modulus: usize,
    poly_size: PolynomialSize,
) -> GlweCiphertext<Vec<u64>>
where
    F: Fn(u64) -> u64,
{
    let base = modulus;
    generate_accumulator_treepbs_base(f, modulus, base, poly_size)
}

pub fn generate_accumulator_treepbs_base<F>(
    f: F,
    modulus: usize,
    base: usize,
    poly_size: PolynomialSize,
) -> GlweCiphertext<Vec<u64>>
where
    F: Fn(u64) -> u64,
{
    let delta = (1_u64 << 63) / modulus as u64;

    // N/(p/2) = size of each block
    let box_size = poly_size.0 / modulus;

    let half_box_size = box_size / 2;

    // Create the accumulator
    let mut accumulator_u64 = vec![0_u64; poly_size.0];

    for i in 0..modulus {
        let index = i as usize * box_size;
        accumulator_u64[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(i as u64 % base as u64) * delta);
    }

    // Negate the first half_box_size coefficients
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    let mut accumulator_ptxt = vec![0_u64; 2 * poly_size.0];

    for (acc_out, acc_in) in accumulator_ptxt[poly_size.0..]
        .iter_mut()
        .zip(accumulator_u64.iter())
    {
        *acc_out = *acc_in;
    }

    GlweCiphertext::from_container(accumulator_ptxt, poly_size)
}

impl<Cont> LwePackingKeyswitchKey<Cont> {
    //Example: We want (ct0 + ct1*x4 + ct2*x10) * poly
    // vec_lwe = [ct0, ct1, ct2]
    // vec_index  = [0, 4, 6]
    /// ```rust
    /// use concrete_commons::dispersion::LogStandardDev;
    /// use concrete_commons::numeric::CastInto;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    ///     MonomialDegree, PolynomialSize,
    /// };
    /// use concrete_core::backends::core::private::crypto::bootstrap::{
    ///     FourierBootstrapKey, FourierBuffers, StandardBootstrapKey,
    /// };
    /// use concrete_core::backends::core::private::crypto::encoding::Plaintext;
    /// use concrete_core::backends::core::private::crypto::glwe::{
    ///     GlweCiphertext, LwePackingKeyswitchKey,
    /// };
    /// use concrete_core::backends::core::private::crypto::lwe::LweCiphertext;
    /// use concrete_core::backends::core::private::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use concrete_core::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use concrete_core::backends::core::private::math::fft::{Complex64, Fft, FourierPolynomial};
    /// use concrete_core::backends::core::private::math::polynomial::Polynomial;
    /// use concrete_core::backends::core::private::math::tensor::AsMutTensor;
    /// // define settings
    /// let polynomial_size = PolynomialSize(1024);
    /// let rlwe_dimension = GlweDimension(1);
    /// let lwe_dimension = LweDimension(630);
    ///
    /// let level = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(7);
    /// let std = LogStandardDev::from_log_standard_dev(-29.);
    ///
    /// let mut secret_generator = SecretRandomGenerator::new(None);
    /// let mut encryption_generator = EncryptionRandomGenerator::new(None);
    ///
    /// let mut rlwe_sk =
    ///     GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    /// let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
    ///
    /// // allocation and generation of the key in coef domain:
    /// let mut coef_bsk = StandardBootstrapKey::allocate(
    ///     0 as u32,
    ///     rlwe_dimension.to_glwe_size(),
    ///     polynomial_size,
    ///     level,
    ///     base_log,
    ///     lwe_dimension,
    /// );
    /// coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);
    ///
    /// // allocation for the bootstrapping key
    /// let mut fourier_bsk = FourierBootstrapKey::allocate(
    ///     Complex64::new(0., 0.),
    ///     rlwe_dimension.to_glwe_size(),
    ///     polynomial_size,
    ///     level,
    ///     base_log,
    ///     lwe_dimension,
    /// );
    ///
    /// let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    /// fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);
    ///
    /// let message = Plaintext(2u32.pow(30));
    ///
    /// let mut lwe_in_1 = LweCiphertext::allocate(0u32, lwe_dimension.to_lwe_size());
    /// let mut lwe_in_2 = LweCiphertext::allocate(0u32, lwe_dimension.to_lwe_size());
    ///
    /// lwe_sk.encrypt_lwe(&mut lwe_in_1, &message, std, &mut encryption_generator);
    /// lwe_sk.encrypt_lwe(&mut lwe_in_2, &message, std, &mut encryption_generator);
    ///
    /// let vec_lwe_in = vec![lwe_in_1, lwe_in_2];
    ///
    /// let modulus = 4;
    /// let base = 2;
    /// let shift = polynomial_size / modulus;
    ///
    /// let mut accumulator =
    ///     GlweCiphertext::allocate(0u32, polynomial_size, rlwe_dimension.to_glwe_size());
    ///
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let mut pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u32,
    ///     level,
    ///     base_log,
    ///     lwe_dimension,
    ///     rlwe_dimension.to_glwe_size().to_glwe_dimension(),
    ///     polynomial_size,
    /// );
    /// pksk.fill_with_packing_keyswitch_key(&lwe_sk, &rlwe_sk, noise, &mut encryption_generator);
    ///
    /// let mut poly = Polynomial::allocate(0u64, polynomial_size);
    /// poly.get_mut_monomial(MonomialDegree(0)).set_coefficient(1);
    ///
    /// //Create the polynomial to multiply the accumulator with
    /// //=======================================================================
    /// let mut poly_block_redundancy = vec![0_u64; poly_size];
    /// let poly_size = accumulator.polynomial_size().0;
    /// let block_size = shift * base;
    ///
    /// for block in poly_block_redundancy.chunks_exact_mut(block_size) {
    ///     block[..shift].fill(1);
    /// }
    ///
    /// let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
    /// //=======================================================================
    ///
    /// pksk.create_accumulator_treepbs(&mut accumulator, &vec_lwe_in, &poly_redundancy, shift);
    /// ```
    pub fn create_accumulator_treepbs<InCont, OutCont, Scalar>(
        &self,
        acc_out: &mut GlweCiphertext<OutCont>,
        vec_lwe: &[LweCiphertext<InCont>],
        poly_redundancy: &Polynomial<Vec<Scalar>>,
        shift: usize,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        LweCiphertext<InCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + CastInto<u64>,
        GlweCiphertext<OutCont>: Clone,
    {
        let mut glwe_buf = acc_out.clone();

        // We reset the output
        acc_out.as_mut_tensor().fill_with(|| Scalar::ZERO);

        // For each LWE ciphertext
        for (i, lwe_in) in vec_lwe.iter().enumerate() {
            // Packing KS from LWE to GLWE, ks resets the glwe to zero before
            self.keyswitch_ciphertext(&mut glwe_buf, lwe_in);

            // Rotate the polynomial of 'shift' coefficients
            glwe_buf
                .as_mut_polynomial_list()
                .update_with_wrapping_monic_monomial_mul(MonomialDegree(shift * i));

            // Add to the output
            acc_out
                .as_mut_tensor()
                .update_with_wrapping_add(glwe_buf.as_tensor());
        }

        let fft = Fft::new(self.output_polynomial_size());

        let half_box_size = shift / 2;
        for mut acc_pol in acc_out.as_mut_polynomial_list().polynomial_iter_mut() {
            let tmp = fourier_multiplication_torus_integer(&fft, &acc_pol, &poly_redundancy);
            // let tmp = karatsuba_multiplication(&acc_pol, &poly_redundancy);

            // Reset the coefficients
            for coef in acc_pol.coefficient_iter_mut() {
                *coef = Scalar::ZERO;
            }

            acc_pol.update_with_wrapping_add(&tmp);

            // Rotate the coefficients
            acc_pol.update_with_wrapping_unit_monomial_div(MonomialDegree(half_box_size));
        }
    }
}
