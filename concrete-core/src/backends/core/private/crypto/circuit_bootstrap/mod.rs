use crate::backends::core::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::core::private::crypto::encoding::Cleartext;
use crate::backends::core::private::crypto::ggsw::{FourierGgswCiphertext, StandardGgswCiphertext};
use crate::backends::core::private::crypto::glwe::{
    FunctionalPackingKeyswitchKey, GlweCiphertext, PackingKeyswitchKey,
};
use crate::backends::core::private::crypto::lwe::LweCiphertext;
use crate::backends::core::private::math::fft::Complex64;
use crate::backends::core::private::math::tensor::{AsMutTensor, AsRefTensor};
use crate::backends::core::private::math::torus::UnsignedTorus;
use concrete_commons::numeric::CastInto;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweSize};
use concrete_fftw::array::AlignedVec;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct DeltaLog(pub usize);

// circuit bootstrap with pfks
pub fn circuit_bootstrap<Scalar, F: Clone + Fn(i64) -> i64>(
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    lwe_in: &LweCiphertext<Vec<Scalar>>,
    mut buffers: &mut FourierBuffers<Scalar>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
    f: F,
    vec_fpksk: &[FunctionalPackingKeyswitchKey<Vec<Scalar>>],
) -> StandardGgswCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus + concrete_commons::numeric::CastFrom<i64>,
{
    if level_cbs.0 < 1 {
        panic!(); //todo
    }
    if base_log_cbs.0 < 1 {
        panic!(); //todo
    }

    // output for every bootstrapping
    let mut lwe_out_bs: LweCiphertext<Vec<Scalar>> = LweCiphertext::allocate(
        Scalar::ZERO,
        LweSize((fourier_bsk.glwe_size().0 - 1) * fourier_bsk.polynomial_size().0 + 1),
    );

    // output for every pfksk
    let mut rlwe_out = GlweCiphertext::allocate(
        Scalar::ZERO,
        vec_fpksk[0].output_polynomial_size(),
        vec_fpksk[0].output_glwe_key_dimension().to_glwe_size(),
    );
    //container for all the result of all the KS
    let mut container = vec![];
    for i in 0..level_cbs.0 {
        lwe_out_bs.as_mut_tensor().fill_with(|| Scalar::ZERO);

        homomorphic_shift(
            fourier_bsk,
            &f,
            &mut lwe_out_bs,
            lwe_in,
            &mut buffers,
            DecompositionLevelCount(i + 1),
            base_log_cbs,
            delta_log,
        );
        for pfksk in vec_fpksk.iter() {
            rlwe_out.as_mut_tensor().fill_with(|| Scalar::ZERO);
            pfksk.functional_keyswitch_ciphertext(&mut rlwe_out, &lwe_out_bs);
            container.append(&mut rlwe_out.tensor.as_mut_container().to_vec());
        }
    }
    StandardGgswCiphertext::from_container(
        container,
        vec_fpksk[0].output_glwe_key_dimension().to_glwe_size(),
        vec_fpksk[0].output_polynomial_size(),
        base_log_cbs,
    )
}

//circuit bootstrap with ksk + external product
pub fn circuit_bootstrap_v1<Scalar, F: Clone + Fn(i64) -> i64>(
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    lwe_in: &LweCiphertext<Vec<Scalar>>,
    mut buffers: &mut FourierBuffers<Scalar>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
    f: F,
    vec_fourier_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    pksk: &PackingKeyswitchKey<Vec<Scalar>>,
) -> StandardGgswCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus + concrete_commons::numeric::CastFrom<i64>,
{
    if level_cbs.0 < 1 {
        panic!(); //todo
    }
    if base_log_cbs.0 < 1 {
        panic!(); //todo
    }

    // output for every bootstrapping
    let mut lwe_out_bs: LweCiphertext<Vec<Scalar>> = LweCiphertext::allocate(
        Scalar::ZERO,
        LweSize((fourier_bsk.glwe_size().0 - 1) * fourier_bsk.polynomial_size().0 + 1),
    );

    let polynomail_size = vec_fourier_ggsw[0].polynomial_size();
    let glwe_size = vec_fourier_ggsw[0].glwe_size();

    // output for external product
    let mut rlwe_out_external_prod =
        GlweCiphertext::allocate(Scalar::ZERO, polynomail_size, glwe_size);

    // output for ksk
    let mut rlwe_out_ks = GlweCiphertext::allocate(
        Scalar::ZERO,
        pksk.output_polynomial_size(),
        pksk.output_glwe_key_dimension().to_glwe_size(),
    );

    //container for all the result of all the KS
    let mut container = vec![];
    for i in 0..level_cbs.0 {
        lwe_out_bs.as_mut_tensor().fill_with(|| Scalar::ZERO);

        homomorphic_shift(
            fourier_bsk,
            &f,
            &mut lwe_out_bs,
            lwe_in,
            &mut buffers,
            DecompositionLevelCount(i + 1),
            base_log_cbs,
            delta_log,
        );

        rlwe_out_ks.as_mut_tensor().fill_with(|| Scalar::ZERO);
        pksk.keyswitch_ciphertext(&mut rlwe_out_ks, &lwe_out_bs);
        for ggsw in vec_fourier_ggsw.iter() {
            rlwe_out_external_prod
                .as_mut_tensor()
                .fill_with(|| Scalar::ZERO);
            ggsw.external_product(&mut rlwe_out_external_prod, &rlwe_out_ks, &mut buffers);
            container.append(&mut rlwe_out_external_prod.tensor.as_mut_container().to_vec());
        }
        container.append(&mut rlwe_out_ks.tensor.as_mut_container().to_vec());
    }

    StandardGgswCiphertext::from_container(container, glwe_size, polynomail_size, base_log_cbs)
}

// circuit bootstrap with pfks
// for lwe with only one bit of message
pub fn circuit_bootstrap_binary<Scalar>(
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    lwe_in: &LweCiphertext<Vec<Scalar>>,
    mut buffers: &mut FourierBuffers<Scalar>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
    vec_fpksk: &[FunctionalPackingKeyswitchKey<Vec<Scalar>>],
) -> StandardGgswCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    if level_cbs.0 < 1 {
        panic!(); //todo
    }
    if base_log_cbs.0 < 1 {
        panic!(); //todo
    }

    // output for every bootstrapping
    let mut lwe_out_bs: LweCiphertext<Vec<Scalar>> = LweCiphertext::allocate(
        Scalar::ZERO,
        LweSize((fourier_bsk.glwe_size().0 - 1) * fourier_bsk.polynomial_size().0 + 1),
    );

    // output for every pfksk
    let mut rlwe_out = GlweCiphertext::allocate(
        Scalar::ZERO,
        vec_fpksk[0].output_polynomial_size(),
        vec_fpksk[0].output_glwe_key_dimension().to_glwe_size(),
    );
    //container for all the result of all the KS
    let mut container = vec![];
    for i in 0..level_cbs.0 {
        lwe_out_bs.as_mut_tensor().fill_with(|| Scalar::ZERO);

        homomorphic_shift_binary(
            fourier_bsk,
            &mut lwe_out_bs,
            lwe_in,
            &mut buffers,
            DecompositionLevelCount(i + 1),
            base_log_cbs,
            delta_log,
        );

        for pfksk in vec_fpksk.iter() {
            rlwe_out.as_mut_tensor().fill_with(|| Scalar::ZERO);
            pfksk.functional_keyswitch_ciphertext(&mut rlwe_out, &lwe_out_bs);
            container.append(&mut rlwe_out.tensor.as_mut_container().to_vec());
        }
    }
    StandardGgswCiphertext::from_container(
        container,
        vec_fpksk[0].output_glwe_key_dimension().to_glwe_size(),
        vec_fpksk[0].output_polynomial_size(),
        base_log_cbs,
    )
}

// circuit bootstrap with  ksk + external product
// for lwe with only one bit of message
pub fn circuit_bootstrap_binary_v1<Scalar>(
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    lwe_in: &LweCiphertext<Vec<Scalar>>,
    mut buffers: &mut FourierBuffers<Scalar>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
    vec_fourier_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    pksk: &PackingKeyswitchKey<Vec<Scalar>>,
) -> StandardGgswCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    if level_cbs.0 < 1 {
        panic!(); //todo
    }
    if base_log_cbs.0 < 1 {
        panic!(); //todo
    }

    // output for every bootstrapping
    let mut lwe_out_bs: LweCiphertext<Vec<Scalar>> = LweCiphertext::allocate(
        Scalar::ZERO,
        LweSize((fourier_bsk.glwe_size().0 - 1) * fourier_bsk.polynomial_size().0 + 1),
    );

    let polynomail_size = vec_fourier_ggsw[0].polynomial_size();
    let glwe_size = vec_fourier_ggsw[0].glwe_size();

    // output for external product
    let mut rlwe_out_external_prod =
        GlweCiphertext::allocate(Scalar::ZERO, polynomail_size, glwe_size);

    // output for ksk
    let mut rlwe_out_ks = GlweCiphertext::allocate(
        Scalar::ZERO,
        pksk.output_polynomial_size(),
        pksk.output_glwe_key_dimension().to_glwe_size(),
    );

    //container for all the result of all the KS
    let mut container = vec![];
    for i in 0..level_cbs.0 {
        lwe_out_bs.as_mut_tensor().fill_with(|| Scalar::ZERO);

        homomorphic_shift_binary(
            fourier_bsk,
            &mut lwe_out_bs,
            lwe_in,
            &mut buffers,
            DecompositionLevelCount(i + 1),
            base_log_cbs,
            delta_log,
        );

        rlwe_out_ks.as_mut_tensor().fill_with(|| Scalar::ZERO);
        pksk.keyswitch_ciphertext(&mut rlwe_out_ks, &lwe_out_bs);
        for ggsw in vec_fourier_ggsw.iter() {
            rlwe_out_external_prod
                .as_mut_tensor()
                .fill_with(|| Scalar::ZERO);
            ggsw.external_product(&mut rlwe_out_external_prod, &rlwe_out_ks, &mut buffers);
            container.append(&mut rlwe_out_external_prod.tensor.as_mut_container().to_vec());
        }
        container.append(&mut rlwe_out_ks.tensor.as_mut_container().to_vec());
    }

    StandardGgswCiphertext::from_container(container, glwe_size, polynomail_size, base_log_cbs)
}

// Create a LUT with the function f
// LUT = [f(0) << (modulus - beta * level),..,f(1) << (modulus - beta * level), ....,-f(0)  << (modulus - beta * level)]
// After evaluate this lut with a bootstrapping
pub fn homomorphic_shift<Scalar, C1, C2, F: Fn(i64) -> i64>(
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    f: F,
    mut lwe_out: &mut LweCiphertext<C1>,
    lwe_in: &LweCiphertext<C2>,
    mut buffers: &mut FourierBuffers<Scalar>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
) where
    Scalar: UnsignedTorus + concrete_commons::numeric::CastFrom<i64>,
    LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
    LweCiphertext<C2>: AsRefTensor<Element = Scalar>,
{
    let log_modulus = Scalar::BITS;

    //redundancy in the LUT = N / (2^{ modulo - log_delta - 1})
    let redundancy = fourier_bsk.polynomial_size().0 / (1 << (log_modulus - delta_log.0 - 1));

    //creation of the LUT for LWE( f(alpha) * 2^{log_q/(log_base * level)})
    let mut look_up_table: Vec<Scalar> =
        vec![Scalar::ZERO; fourier_bsk.polynomial_size().0 * fourier_bsk.glwe_size().0];
    for i in 1..(1 << (log_modulus - delta_log.0 - 1)) {
        for j in 0..redundancy {
            look_up_table[i * redundancy
                + j
                + fourier_bsk.polynomial_size().0 * (fourier_bsk.glwe_size().0 - 1)
                - redundancy / 2] =
                ((f(i as i64)) << (log_modulus - base_log_cbs.0 * level_cbs.0)).cast_into();
        }
    }
    for j in 0..redundancy {
        if j < redundancy / 2 {
            look_up_table[j + fourier_bsk.polynomial_size().0 * (fourier_bsk.glwe_size().0 - 1)] =
                ((f(0)) << (log_modulus - base_log_cbs.0 * level_cbs.0)).cast_into();
        } else {
            look_up_table
                [fourier_bsk.polynomial_size().0 * (fourier_bsk.glwe_size().0) - redundancy + j] =
                Scalar::ZERO.wrapping_sub(
                    ((f(0)) << (log_modulus - base_log_cbs.0 * level_cbs.0)).cast_into(),
                );
        }
    }
    let accumulator = GlweCiphertext::from_container(look_up_table, fourier_bsk.polynomial_size());
    fourier_bsk.bootstrap(&mut lwe_out, lwe_in, &accumulator, &mut buffers);
}

// homomorphic shift for LWE without padding bit
pub fn homomorphic_shift_binary<Scalar, C1, C2>(
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    mut lwe_out: &mut LweCiphertext<C1>,
    lwe_in: &LweCiphertext<C2>,
    mut buffers: &mut FourierBuffers<Scalar>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    delta_log: DeltaLog,
) where
    Scalar: UnsignedTorus,
    LweCiphertext<C1>: AsMutTensor<Element = Scalar>,
    LweCiphertext<C2>: AsRefTensor<Element = Scalar>,
{
    let log_modulus = Scalar::BITS;
    let lwe_in_size = lwe_in.lwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();

    let mut lwe_tmp = LweCiphertext::allocate(Scalar::ZERO, lwe_in_size);
    lwe_tmp.fill_with_scalar_mul(
        &lwe_in,
        &Cleartext(Scalar::ONE << (log_modulus - delta_log.0 - 1)),
    );

    //add q/4
    let mut cont = vec![Scalar::ZERO; lwe_in_size.0];
    cont[lwe_in_size.0 - 1] = Scalar::ONE << (log_modulus - 2);
    let tmp = LweCiphertext::from_container(cont);
    lwe_tmp.update_with_add(&tmp);

    let mut look_up_table: Vec<Scalar> =
        vec![Scalar::ZERO; polynomial_size.0 * (fourier_bsk.glwe_size().0 - 1)];
    look_up_table.append(&mut vec![
        Scalar::ZERO.wrapping_sub(
            Scalar::ONE << (log_modulus - 1 - base_log_cbs.0 * level_cbs.0)
        );
        polynomial_size.0
    ]);
    let accumulator = GlweCiphertext::from_container(look_up_table, polynomial_size);
    fourier_bsk.bootstrap(&mut lwe_out, &lwe_tmp, &accumulator, &mut buffers);

    let mut cont = vec![Scalar::ZERO; polynomial_size.0 * (fourier_bsk.glwe_size().0 - 1) + 1];
    cont[polynomial_size.0 * (fourier_bsk.glwe_size().0 - 1)] =
        Scalar::ONE << (log_modulus - 1 - base_log_cbs.0 * level_cbs.0);
    let tmp = LweCiphertext::from_container(cont);

    lwe_out.update_with_add(&tmp);
}
