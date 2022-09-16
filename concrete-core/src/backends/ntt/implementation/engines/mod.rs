//! A module containing the [engines](crate::specification::engines) exposed by the ntt backend.
use crate::backends::ntt::private::crypto::bootstrap::FourierBuffers;
use crate::backends::ntt::private::math::transform::Ntt;
use crate::prelude::{GlweSize, PolynomialSize, PolynomialSizeLog};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::backends::ntt::private::math::params::params_32_1024::{
    INVROOTS_32_1024, MOD_32_1024, NINV_32_1024, ROOTS_32_1024,
};
use crate::backends::ntt::private::math::params::params_32_128::{
    INVROOTS_32_128, MOD_32_128, NINV_32_128, ROOTS_32_128,
};
use crate::backends::ntt::private::math::params::params_32_2048::{
    INVROOTS_32_2048, MOD_32_2048, NINV_32_2048, ROOTS_32_2048,
};
use crate::backends::ntt::private::math::params::params_32_256::{
    INVROOTS_32_256, MOD_32_256, NINV_32_256, ROOTS_32_256,
};
use crate::backends::ntt::private::math::params::params_32_4096::{
    INVROOTS_32_4096, MOD_32_4096, NINV_32_4096, ROOTS_32_4096,
};
use crate::backends::ntt::private::math::params::params_32_512::{
    INVROOTS_32_512, MOD_32_512, NINV_32_512, ROOTS_32_512,
};

use crate::backends::ntt::private::math::params::params_64_1024::{
    INVROOTS_64_1024, MOD_64_1024, NINV_64_1024, ROOTS_64_1024,
};
use crate::backends::ntt::private::math::params::params_64_128::{
    INVROOTS_64_128, MOD_64_128, NINV_64_128, ROOTS_64_128,
};
use crate::backends::ntt::private::math::params::params_64_2048::{
    INVROOTS_64_2048, MOD_64_2048, NINV_64_2048, ROOTS_64_2048,
};
use crate::backends::ntt::private::math::params::params_64_256::{
    INVROOTS_64_256, MOD_64_256, NINV_64_256, ROOTS_64_256,
};
use crate::backends::ntt::private::math::params::params_64_4096::{
    INVROOTS_64_4096, MOD_64_4096, NINV_64_4096, ROOTS_64_4096,
};
use crate::backends::ntt::private::math::params::params_64_512::{
    INVROOTS_64_512, MOD_64_512, NINV_64_512, ROOTS_64_512,
};

// /// The error which can occur in the execution of FHE operations.
#[derive(Debug)]
pub enum NttError {
    UnsupportedPolynomialSize,
}

impl Display for NttError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NttError::UnsupportedPolynomialSize => {
                write!(
                    f,
                    "The NTT Backend only supports polynomials of size: 128, 256, 512, \
                1024, 2048, 4096."
                )
            }
        }
    }
}

impl Error for NttError {}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct FourierBufferKey(pub PolynomialSize, pub GlweSize);

/// The main engine exposed by the ntt backend.
pub struct NttEngine {
    // We need to set up parameters for every polynomial size, which we do when creating the
    // engine, see the implementation of `AbstractEngine::new` for `NttEngine`. These are stored
    // in the maps below.
    ntts32: BTreeMap<PolynomialSize, Ntt<u64>>,
    ntts64: BTreeMap<PolynomialSize, Ntt<u128>>,

    // We need additional buffers for the bootstrapping/external product. Similar to the
    // FFTW engine, these are created on demand and reused as needed. These buffers also
    // each contain a clone of the correct `Ntt` from the maps above for convenience.
    buffers_u32: BTreeMap<FourierBufferKey, FourierBuffers<u32, u64>>,
    buffers_u64: BTreeMap<FourierBufferKey, FourierBuffers<u64, u128>>,
}

impl NttEngine {
    pub(crate) fn get_u32_buffer(
        &mut self,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> &mut FourierBuffers<u32, u64> {
        let buffer_key = FourierBufferKey(poly_size, glwe_size);
        let ntt = self.ntts32.get_mut(&poly_size).unwrap();
        // We clone the `Ntt` object, because every buffer object needs their own instantiation,
        // since it contains a mutable buffer.
        self.buffers_u32
            .entry(buffer_key)
            .or_insert_with(|| FourierBuffers::new(poly_size, glwe_size, ntt.clone()))
    }

    pub(crate) fn get_u64_buffer(
        &mut self,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> &mut FourierBuffers<u64, u128> {
        let buffer_key = FourierBufferKey(poly_size, glwe_size);
        let ntt = self.ntts64.get_mut(&poly_size).unwrap();
        // We clone the `Ntt` object, because every buffer object needs their own instantiation,
        // since it contains a mutable buffer.
        self.buffers_u64
            .entry(buffer_key)
            .or_insert_with(|| FourierBuffers::new(poly_size, glwe_size, ntt.clone()))
    }
}

impl AbstractEngineSeal for NttEngine {}

impl AbstractEngine for NttEngine {
    type EngineError = NttError;

    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let mut ntt32: BTreeMap<PolynomialSize, Ntt<u64>> = Default::default();
        let mut ntt64: BTreeMap<PolynomialSize, Ntt<u128>> = Default::default();

        macro_rules! setup {
            ($Ntt: ident,
            $Type: ty,
            $PolySize: expr,
            $PolySizeLog: expr,
            $Mod: ident,
            $Roots: ident,
            $RootsInv: ident,
            $Ninv: ident) => {
                let roots: Vec<ModQ<$Type>> = $Roots
                    .to_vec()
                    .iter()
                    .map(|a| <ModQ<$Type>>::new(*a as $Type, $Mod as $Type))
                    .collect();
                let roots_inv: Vec<ModQ<$Type>> = $RootsInv
                    .to_vec()
                    .iter()
                    .map(|a| <ModQ<$Type>>::new(*a as $Type, $Mod as $Type))
                    .collect();
                let poly_size = PolynomialSize($PolySize);
                $Ntt.insert(
                    poly_size,
                    Ntt::new(
                        poly_size,
                        PolynomialSizeLog($PolySizeLog),
                        roots,
                        roots_inv,
                        <ModQ<$Type>>::new($Ninv as $Type, $Mod as $Type),
                    ),
                );
            };
        }

        setup!(
            ntt32,
            u64,
            128,
            7,
            MOD_32_128,
            ROOTS_32_128,
            INVROOTS_32_128,
            NINV_32_128
        );
        setup!(
            ntt32,
            u64,
            256,
            8,
            MOD_32_256,
            ROOTS_32_256,
            INVROOTS_32_256,
            NINV_32_256
        );
        setup!(
            ntt32,
            u64,
            512,
            9,
            MOD_32_512,
            ROOTS_32_512,
            INVROOTS_32_512,
            NINV_32_512
        );
        setup!(
            ntt32,
            u64,
            1024,
            10,
            MOD_32_1024,
            ROOTS_32_1024,
            INVROOTS_32_1024,
            NINV_32_1024
        );
        setup!(
            ntt32,
            u64,
            2048,
            11,
            MOD_32_2048,
            ROOTS_32_2048,
            INVROOTS_32_2048,
            NINV_32_2048
        );
        setup!(
            ntt32,
            u64,
            4096,
            12,
            MOD_32_4096,
            ROOTS_32_4096,
            INVROOTS_32_4096,
            NINV_32_4096
        );

        setup!(
            ntt64,
            u128,
            128,
            7,
            MOD_64_128,
            ROOTS_64_128,
            INVROOTS_64_128,
            NINV_64_128
        );
        setup!(
            ntt64,
            u128,
            256,
            8,
            MOD_64_256,
            ROOTS_64_256,
            INVROOTS_64_256,
            NINV_64_256
        );
        setup!(
            ntt64,
            u128,
            512,
            9,
            MOD_64_512,
            ROOTS_64_512,
            INVROOTS_64_512,
            NINV_64_512
        );
        setup!(
            ntt64,
            u128,
            1024,
            10,
            MOD_64_1024,
            ROOTS_64_1024,
            INVROOTS_64_1024,
            NINV_64_1024
        );
        setup!(
            ntt64,
            u128,
            2048,
            11,
            MOD_64_2048,
            ROOTS_64_2048,
            INVROOTS_64_2048,
            NINV_64_2048
        );
        setup!(
            ntt64,
            u128,
            4096,
            12,
            MOD_64_4096,
            ROOTS_64_4096,
            INVROOTS_64_4096,
            NINV_64_4096
        );

        let ntt_engine = NttEngine {
            ntts32: ntt32,
            ntts64: ntt64,
            buffers_u32: Default::default(),
            buffers_u64: Default::default(),
        };

        Ok(ntt_engine)
    }
}

mod glwe_ciphertext_conversion;
