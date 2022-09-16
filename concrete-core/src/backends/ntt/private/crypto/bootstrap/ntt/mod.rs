mod buffers;

use crate::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::backends::ntt::private::math::transform::Ntt;
use crate::commons::crypto::bootstrap::StandardBootstrapKey;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::crypto::lwe::LweCiphertext;
use crate::commons::math::tensor::{
    ck_dim_div, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::commons::math::torus::UnsignedTorus;

use crate::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LutCountLog, LweDimension,
    ModulusSwitchOffset, MonomialDegree, PolynomialSize,
};

pub use buffers::BootstrapBuffers;

/// A bootstrapping key in the NTT domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttBootstrapKey<Cont> {
    // The tensor containing the actual data of the secret key.
    tensor: Tensor<Cont>,
    // The size of the polynomials
    poly_size: PolynomialSize,
    // The size of the GLWE
    glwe_size: GlweSize,
    // The decomposition parameters
    decomp_level: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
}

impl<NttScalar> NttBootstrapKey<Vec<ModQ<NttScalar>>>
where
    NttScalar: UnsignedInteger,
{
    /// Allocates a new bootstrapping key whose polynomials coefficients are all empty.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(256));
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// assert_eq!(bsk.input_lwe_dimension(), LweDimension(4));
    /// ```
    pub fn allocate(
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        key_size: LweDimension,
    ) -> Self {
        let tensor = Tensor::from_container(vec![
            <ModQ<NttScalar>>::empty();
            key_size.0
                * decomp_level.0
                * glwe_size.0
                * glwe_size.0
                * poly_size.0
        ]);

        NttBootstrapKey {
            tensor,
            poly_size,
            glwe_size,
            decomp_level,
            decomp_base_log,
        }
    }
}

impl<Cont> NttBootstrapKey<Cont> {
    /// Creates a bootstrapping key from an existing container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_256::MOD_32_256;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let vector = vec![ModQ::new(0u64, MOD_32_256); 256 * 5 * 4 * 4 * 15];
    /// let bsk = NttBootstrapKey::from_container(
    ///     vector.as_slice(),
    ///     GlweSize(4),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(5),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(256));
    /// assert_eq!(bsk.glwe_size(), GlweSize(4));
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(5));
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(4));
    /// assert_eq!(bsk.input_lwe_dimension(), LweDimension(15));
    /// ```
    pub fn from_container(
        cont: Cont,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() =>
            decomp_level.0,
            glwe_size.0 * glwe_size.0,
            poly_size.0
        );
        NttBootstrapKey {
            tensor,
            poly_size,
            glwe_size,
            decomp_level,
            decomp_base_log,
        }
    }

    /// Fills a NTT bootstrapping key with the NTT transform of a bootstrapping key in
    /// coefficient domain.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_256::{
    ///     INVROOTS_32_256, MOD_32_256, NINV_32_256, ROOTS_32_256,
    /// };
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    ///     PolynomialSizeLog,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// let mut ntt_bsk = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// let poly_size = PolynomialSize(256);
    /// let log_size = PolynomialSizeLog(8);
    /// let q: u64 = MOD_32_256;
    /// let roots: Vec<ModQ<u64>> = ROOTS_32_256
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let roots_inv: Vec<ModQ<u64>> = INVROOTS_32_256
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let n_inv = ModQ::new(NINV_32_256, q);
    /// let mut ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    /// ntt_bsk.fill_with_forward_ntt(&bsk, &mut ntt);
    /// ```
    pub fn fill_with_forward_ntt<InputCont, Scalar, NttScalar>(
        &mut self,
        coef_bsk: &StandardBootstrapKey<InputCont>,
        ntt: &mut Ntt<NttScalar>,
    ) where
        Cont: AsMutSlice<Element = ModQ<NttScalar>>,
        StandardBootstrapKey<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + CastInto<NttScalar>,
        NttScalar: UnsignedInteger,
    {
        // We move every GGSW to the NTT domain.
        let iterator = self.ggsw_iter_mut().zip(coef_bsk.ggsw_iter());
        for (mut ntt_ggsw, coef_ggsw) in iterator {
            ntt_ggsw.fill_with_forward_ntt(&coef_ggsw, ntt);
        }
    }

    /// Returns the size of the polynomials used in the bootstrapping key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(256));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the size of the GLWE ciphertexts used in the bootstrapping key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the dimension of the output LWE ciphertext after a bootstrap.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.output_lwe_dimension(), LweDimension(1536));
    /// ```
    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension((self.glwe_size.0 - 1) * self.poly_size.0)
    }

    /// Returns the number of levels used to decompose the key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.decomp_level
    }

    /// Returns the logarithm of the base used to decompose the key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns the size of the LWE encrypted key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.input_lwe_dimension(), LweDimension(4));
    /// ```
    pub fn input_lwe_dimension(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.poly_size.0,
            self.glwe_size.0 * self.glwe_size.0,
            self.decomp_level.0
        );
        LweDimension(
            self.as_tensor().len()
                / (self.glwe_size.0 * self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0),
        )
    }

    /// Returns an iterator over the borrowed GGSW ciphertext composing the key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// for ggsw in bsk.ggsw_iter() {
    ///     assert_eq!(ggsw.polynomial_size(), PolynomialSize(256));
    ///     assert_eq!(ggsw.glwe_size(), GlweSize(7));
    ///     assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// }
    /// assert_eq!(bsk.ggsw_iter().count(), 4);
    /// ```
    pub fn ggsw_iter<NttScalar: UnsignedInteger>(
        &self,
    ) -> impl Iterator<Item = NttGgswCiphertext<&[ModQ<NttScalar>]>>
    where
        Self: AsRefTensor<Element = ModQ<NttScalar>>,
    {
        let chunks_size =
            self.glwe_size.0 * self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let rlwe_size = self.glwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .map(move |tensor| {
                NttGgswCiphertext::from_container(
                    tensor.into_container(),
                    rlwe_size,
                    poly_size,
                    base_log,
                )
            })
    }

    /// Returns an iterator over the mutably borrowed GGSW ciphertext composing the key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::NttBootstrapKey;
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_256::MOD_32_256;
    /// use concrete_core::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let mut bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// for mut ggsw in bsk.ggsw_iter_mut() {
    ///     ggsw.as_mut_tensor()
    ///         .fill_with_element(ModQ::new(1u64, MOD_32_256));
    /// }
    /// assert!(bsk
    ///     .as_tensor()
    ///     .iter()
    ///     .all(|a| *a == ModQ::new(1u64, MOD_32_256)));
    /// assert_eq!(bsk.ggsw_iter_mut().count(), 4);
    /// ```
    pub fn ggsw_iter_mut<NttScalar: UnsignedInteger>(
        &mut self,
    ) -> impl Iterator<Item = NttGgswCiphertext<&mut [ModQ<NttScalar>]>>
    where
        Self: AsMutTensor<Element = ModQ<NttScalar>>,
    {
        let chunks_size =
            self.glwe_size.0 * self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let rlwe_size = self.glwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |tensor| {
                NttGgswCiphertext::from_container(
                    tensor.into_container(),
                    rlwe_size,
                    poly_size,
                    base_log,
                )
            })
    }

    fn blind_rotate<C2, NttScalar, Scalar>(
        &self,
        buffers: &mut BootstrapBuffers<Scalar, NttScalar>,
        lwe: &LweCiphertext<C2>,
    ) where
        LweCiphertext<C2>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<Vec<Scalar>>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = ModQ<NttScalar>>,
        NttScalar: UnsignedInteger,
        Scalar: UnsignedTorus + CastInto<NttScalar> + CastFrom<NttScalar>,
    {
        // We unpack the lwe ciphertext.
        let (lwe_body, lwe_mask) = lwe.get_body_and_mask();
        let lut = &mut buffers.lut_buffer;

        // We perform the initial clear rotation by performing lut <- lut * X^{-body_hat}
        let lut_poly_size = lut.polynomial_size();
        lut.as_mut_polynomial_list()
            .update_with_wrapping_monic_monomial_div(pbs_modulus_switch(
                lwe_body.0,
                lut_poly_size,
                ModulusSwitchOffset(0),
                LutCountLog(0),
            ));

        // We initialize the ct_0 and ct_1 used for the successive cmuxes
        let ct_0 = lut;
        let mut ct_1 = GlweCiphertext::allocate(Scalar::ZERO, ct_0.polynomial_size(), ct_0.size());

        // We iterate over the bootstrap key elements and perform the blind rotation.
        for (lwe_mask_element, bootstrap_key_ggsw) in
            lwe_mask.mask_element_iter().zip(self.ggsw_iter())
        {
            // We copy ct_0 to ct_1
            ct_1.as_mut_tensor()
                .as_mut_slice()
                .copy_from_slice(ct_0.as_tensor().as_slice());

            // If the mask is not zero, we perform the cmux
            if *lwe_mask_element != Scalar::ZERO {
                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                ct_1.as_mut_polynomial_list()
                    .update_with_wrapping_monic_monomial_mul(pbs_modulus_switch(
                        *lwe_mask_element,
                        lut_poly_size,
                        ModulusSwitchOffset(0),
                        LutCountLog(0),
                    ));
                // We perform the cmux.
                bootstrap_key_ggsw.cmux(
                    ct_0,
                    &mut ct_1,
                    &mut buffers.rounded_buffer,
                    &mut buffers.ntt,
                );
            }
        }
    }
}

// This function switches modulus for a single coefficient of a ciphertext,
// only in the context of a PBS
//
// offset: the number of msb discarded
// lut_count_log: the right padding
pub fn pbs_modulus_switch<Scalar>(
    input: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> MonomialDegree
where
    Scalar: UnsignedInteger,
{
    // First, do the left shift (we discard the offset msb)
    let mut output = input << offset.0;
    // Start doing the right shift
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += output & Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    // Apply the lsb padding
    output <<= lut_count_log.0;
    MonomialDegree(output.cast_into() as usize)
}

impl<Cont, NttScalar> NttBootstrapKey<Cont>
where
    Self: AsRefTensor<Element = ModQ<NttScalar>>,
    NttScalar: UnsignedInteger,
{
    /// Performs a bootstrap of an lwe ciphertext, with a given accumulator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_core::backends::ntt::private::crypto::bootstrap::{
    ///     BootstrapBuffers, NttBootstrapKey,
    /// };
    /// use concrete_core::backends::ntt::private::math::mod_q::ModQ;
    /// use concrete_core::backends::ntt::private::math::params::params_32_1024::{
    ///     INVROOTS_32_1024, MOD_32_1024, NINV_32_1024, ROOTS_32_1024,
    /// };
    /// use concrete_core::backends::ntt::private::math::transform::Ntt;
    /// use concrete_core::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use concrete_core::commons::crypto::encoding::Plaintext;
    /// use concrete_core::commons::crypto::glwe::GlweCiphertext;
    /// use concrete_core::commons::crypto::lwe::LweCiphertext;
    /// use concrete_core::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use concrete_core::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use concrete_core::commons::math::tensor::AsMutTensor;
    /// use concrete_core::commons::numeric::CastInto;
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     LweSize, PolynomialSize, PolynomialSizeLog,
    /// };
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
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
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
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
    /// let mut ntt_bsk: NttBootstrapKey<Vec<ModQ<u64>>> = NttBootstrapKey::allocate(
    ///     rlwe_dimension.to_glwe_size(),
    ///     polynomial_size,
    ///     level,
    ///     base_log,
    ///     lwe_dimension,
    /// );
    ///
    /// let poly_size = PolynomialSize(1024);
    /// let log_size = PolynomialSizeLog(10);
    /// let q: u64 = MOD_32_1024;
    /// let roots: Vec<ModQ<u64>> = ROOTS_32_1024
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let roots_inv: Vec<ModQ<u64>> = INVROOTS_32_1024
    ///     .to_vec()
    ///     .iter()
    ///     .map(|a| <ModQ<u64>>::new(*a as u64, q))
    ///     .collect();
    /// let n_inv = ModQ::new(NINV_32_1024, q);
    /// let mut ntt = Ntt::new(poly_size, log_size, roots, roots_inv, n_inv);
    ///
    /// ntt_bsk.fill_with_forward_ntt(&coef_bsk, &mut ntt);
    ///
    /// let message = Plaintext(2u32.pow(30));
    ///
    /// let mut lwe_in = LweCiphertext::allocate(0u32, lwe_dimension.to_lwe_size());
    /// let mut lwe_out =
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
    /// let mut buffers = BootstrapBuffers::new(ntt_bsk.polynomial_size(), ntt_bsk.glwe_size(), ntt);
    /// // bootstrap
    /// ntt_bsk.bootstrap(&mut lwe_out, &lwe_in, &accumulator, &mut buffers);
    /// ```
    pub fn bootstrap<C1, C2, C3, Scalar>(
        &self,
        lwe_out: &mut LweCiphertext<C1>,
        lwe_in: &LweCiphertext<C2>,
        accumulator: &GlweCiphertext<C3>,
        buffers: &mut BootstrapBuffers<Scalar, NttScalar>,
    ) where
        LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
        LweCiphertext<C2>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<C3>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + CastInto<NttScalar> + CastFrom<NttScalar>,
    {
        // We retrieve the accumulator buffer, and fill it with the input accumulator values.
        {
            let local_accumulator = &mut buffers.lut_buffer;
            local_accumulator
                .as_mut_tensor()
                .as_mut_slice()
                .copy_from_slice(accumulator.as_tensor().as_slice());
        }

        // We perform the blind rotate
        self.blind_rotate(buffers, lwe_in);

        // We perform the extraction of the first sample.
        let local_accumulator = &mut buffers.lut_buffer;
        local_accumulator.fill_lwe_with_sample_extraction(lwe_out, MonomialDegree(0));
    }
}

impl<Element, Cont> AsRefTensor for NttBootstrapKey<Cont>
where
    Cont: AsRefSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.tensor
    }
}

impl<Element, Cont> AsMutTensor for NttBootstrapKey<Cont>
where
    Cont: AsMutSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.tensor
    }
}

impl<Cont> IntoTensor for NttBootstrapKey<Cont>
where
    Cont: AsRefSlice,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.tensor
    }
}
