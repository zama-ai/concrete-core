use crate::backends::core::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::core::private::crypto::circuit_bootstrap::{
    circuit_bootstrap, circuit_bootstrap_binary, circuit_bootstrap_binary_v1, circuit_bootstrap_v1,
    DeltaLog,
};
use crate::backends::core::private::crypto::ggsw::FourierGgswCiphertext;
use crate::backends::core::private::crypto::glwe::{
    FunctionalPackingKeyswitchKey, GlweCiphertext, PackingKeyswitchKey,
};
use crate::backends::core::private::crypto::lwe::LweCiphertext;
use crate::backends::core::private::math::fft::{AlignedVec, Complex64};
use crate::backends::core::private::math::tensor::{
    AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor,
};
use crate::backends::core::private::math::torus::UnsignedTorus;
use concrete_commons::parameters::DecompositionBaseLog;
use concrete_commons::parameters::DecompositionLevelCount;
use concrete_commons::parameters::GlweDimension;
use concrete_commons::parameters::PolynomialSize;
use concrete_commons::parameters::{LweSize, MonomialDegree};

#[cfg(test)]
mod tests;
/*
// ggsw are store from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
pub fn vertical_packing<Scalar>(
    lut: Vec<Scalar>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
) -> LweCiphertext<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
{
    let polynomial_size = vec_ggsw[0].polynomial_size();
    let glwe_dimension : GlweDimension = GlweDimension(vec_ggsw[0].glwe_size().0 - 1);

    // the 'big' lut must be divisible in several lut of size polynomial_size
    if lut.len() != polynomial_size.0 {
        panic!(); //TODO manage error
    }

    // find the number of lut in the 'big' lut
    let mut log_lut_number = 0;
    while polynomial_size.0 != 1 << log_lut_number {
        log_lut_number += 1;
    }
    // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
    // Blind rotation
    if log_lut_number > vec_ggsw.len(){
        log_lut_number = vec_ggsw.len();
    }

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = vec_ggsw.split_at(vec_ggsw.len() - log_lut_number);

    let mut lut = cmux_tree_memory_optimized(lut, &cmux_ggsw.to_vec(), buffers, glwe_dimension);
    blind_rotate(&mut lut, &br_ggsw.to_vec(), buffers);

    // sample extract of the RLWE of the Vertical packing
    let mut lwe_out = LweCiphertext::allocate(
        Scalar::ZERO,
        LweSize(polynomial_size.0 * (vec_ggsw[0].glwe_size().0 - 1) + 1),
    );
    lut.fill_lwe_with_sample_extraction(&mut lwe_out, MonomialDegree(0));
    lwe_out
}


pub fn cmux_tree_memory_optimized<Scalar>(
    lut: Vec<Scalar>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
    glwe_dimension: GlweDimension,
) -> GlweCiphertext<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
{
    if !vec_ggsw.is_empty() {
        let nb_layer = vec_ggsw.len();
        let mask_and_body =
            vec![Scalar::ZERO; lut.len() * (glwe_dimension.0 + 1)];

        let mut result= GlweCiphertext::from_container(mask_and_body.clone(), PolynomialSize(lut.len()));

        let mut rlwe_lut = GlweCiphertext::from_container(mask_and_body.clone(), PolynomialSize(lut
            .len()));
        let mut t_0 = vec![rlwe_lut.clone(); nb_layer];
        let mut t_1 = vec![rlwe_lut; nb_layer];
        let mut t_fill = vec![0_usize;nb_layer];
        let mut cmux_buffer =  GlweCiphertext::from_container(mask_and_body, PolynomialSize(lut.len
        ()));
        for _ in 0..1<<(nb_layer - 1){
            //load 2 trivial CT with LUT
            for (coef_0, lut_coef) in t_0[0].get_mut_body().as_mut_polynomial()
                .coefficient_iter_mut().zip(lut.iter()){
                //
                *coef_0 = *lut_coef;
            }
            for (coef_1, lut_coef) in t_1[0].get_mut_body().as_mut_polynomial()
                .coefficient_iter_mut().zip(lut.iter()){
                //
                *coef_1 = *lut_coef;
            }
            t_fill[0] = 2;
            for (j, ggsw ) in vec_ggsw.iter().rev().enumerate(){
                if t_fill[j] == 2 {
                    if j != nb_layer - 1 {
                        if t_fill[j + 1] == 0_usize {
                            cmux_with_output(&t_0[j].clone(), &t_1[j], &mut t_0[j + 1], &mut cmux_buffer, ggsw,
                                             buffers);
                        } else {
                            cmux_with_output(&t_0[j], &t_1[j].clone(), &mut t_1[j + 1], &mut
                                cmux_buffer,
                                             ggsw,
                                             buffers);
                        }
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;
                    } else {
                        cmux_with_output(&t_0[j].clone(), &t_1[j], &mut result, &mut cmux_buffer, ggsw, buffers);
                    }
                } else {
                    break;
                }
            }
        }
        return result
    } else {
        let mut mask_and_body = vec![Scalar::ZERO; lut.len() * glwe_dimension.0];      //TODO
        // error for GLWE
        mask_and_body.append(&mut lut.to_vec());
        let rlwe_lut = GlweCiphertext::from_container(mask_and_body, PolynomialSize(lut.len()));
        return rlwe_lut
    }
}

pub fn cmux_tree<Scalar>(
    lut: Vec<Scalar>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
    glwe_dimension: GlweDimension,
) -> GlweCiphertext<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
{
    let mut vec_rlwe = vec![];
    if !vec_ggsw.is_empty() {
        let polynomial_size = vec_ggsw[0].polynomial_size();
        if lut.len() % polynomial_size.0 != 0 {
            panic!(); //TODO manage error
        }

        // we can't return only one look up table of size polynomial_size
        // Big lut to small or to big.
        //if lut.len() / polynomial_size.0 != 1 << vec_ggsw.len() {
        //    panic!(); //TODO manage error
        //}

        //creation of all the sub_lut encrypted in RLWE
        let mut mask_and_body =
            vec![Scalar::ZERO; polynomial_size.0 * (vec_ggsw[0].glwe_size().0 - 1)];
        mask_and_body.append(&mut lut.to_vec());
        let mut rlwe_lut = GlweCiphertext::from_container(mask_and_body, polynomial_size);
        let mut tmp = 0;
        for ggsw in vec_ggsw.iter().rev() {
            if tmp == 0 {
                for _ in 0..(1 << (vec_ggsw.len()-1)) {
                    //let mut ct_0 = &mut rlwe_lut;
                    let mut ct_1 = rlwe_lut.clone();
                    cmux(&mut ct_1, &mut rlwe_lut.clone(), ggsw, buffers);
                    vec_rlwe.push(ct_1.clone());
                }
                tmp += 1;
            } else {
                for i in 0..vec_rlwe.len() / 2 {
                    //let mut ct_0 = vec_rlwe.get_mut(2 * i).unwrap();
                    //let mut ct_1 = vec_rlwe.get_mut(2 * i + 1).unwrap();
                    let mut ct_0 = vec_rlwe.get_mut(2 * i).unwrap().clone();
                    let mut ct_1 = vec_rlwe.get_mut(2 * i + 1).unwrap().clone();
                    cmux(&mut ct_0, &mut ct_1, ggsw, buffers);
                    vec_rlwe[i] = ct_0.clone();
                }
                vec_rlwe.truncate(vec_rlwe.len() / 2);
            }
        }
    } else {
        let mut mask_and_body = vec![Scalar::ZERO; lut.len() * glwe_dimension.0];
        // error for GLWE
        mask_and_body.append(&mut lut.to_vec());
        let rlwe_lut = GlweCiphertext::from_container(mask_and_body, PolynomialSize(lut.len()));
        vec_rlwe.push(rlwe_lut);
    }
    vec_rlwe[0].clone()
}
 */

// here can be use for big lut ( before it's juste for on lut which is duplicate )

// ggsw are store from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
pub fn vertical_packing<Scalar>(
    lut: Vec<Scalar>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
) -> LweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    let polynomial_size = vec_ggsw[0].polynomial_size();
    let glwe_dimension: GlweDimension = GlweDimension(vec_ggsw[0].glwe_size().0 - 1);

    // the 'big' lut must be divisible in several lut of size polynomial_size
    if lut.len() % polynomial_size.0 != 0 {
        panic!(); //TODO manage error
    }
    if lut.len() / (1 << vec_ggsw.len()) < 1 {
        panic!(); //TODO manage error
    }

    // find the number of lut in the 'big' lut
    let mut log_lut_number = 0;
    while lut.len() / polynomial_size.0 > (1 << log_lut_number) {
        log_lut_number += 1;
    }

    // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
    // Blind rotation
    if log_lut_number > vec_ggsw.len() {
        log_lut_number = 0;
    }

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = vec_ggsw.split_at(log_lut_number);
    let mut lut = cmux_tree_memory_optimized(lut, &cmux_ggsw.to_vec(), buffers, glwe_dimension);
    blind_rotate(&mut lut, &br_ggsw.to_vec(), buffers);

    // sample extract of the RLWE of the Vertical packing
    let mut lwe_out = LweCiphertext::allocate(
        Scalar::ZERO,
        LweSize(polynomial_size.0 * (vec_ggsw[0].glwe_size().0 - 1) + 1),
    );
    lut.fill_lwe_with_sample_extraction(&mut lwe_out, MonomialDegree(0));
    lwe_out
}

pub fn cmux_tree<Scalar>(
    lut: Vec<Scalar>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
    glwe_dimension: GlweDimension,
) -> GlweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    let mut vec_rlwe = vec![];
    if !vec_ggsw.is_empty() {
        let polynomial_size = vec_ggsw[0].polynomial_size();
        if lut.len() % polynomial_size.0 != 0 {
            panic!(); //TODO manage error
        }

        // we can't return only one look up table of size polynomial_size
        // Big lut to small or to big.
        if lut.len() / polynomial_size.0 != 1 << vec_ggsw.len() {
            panic!(); //TODO manage error
        }

        //creation of all the sub_lut encrypted in RLWE
        for ith_lut in lut.chunks(polynomial_size.0).into_iter() {
            let mut mask_and_body =
                vec![Scalar::ZERO; polynomial_size.0 * (vec_ggsw[0].glwe_size().0 - 1)];
            mask_and_body.append(&mut ith_lut.to_vec());
            let rlwe_lut = GlweCiphertext::from_container(mask_and_body, polynomial_size);
            vec_rlwe.push(rlwe_lut);
        }
        for ggsw in vec_ggsw.iter().rev() {
            for i in 0..vec_rlwe.len() / 2 {
                let mut ct_0 = vec_rlwe.get_mut(2 * i).unwrap().clone();
                let mut ct_1 = vec_rlwe.get_mut(2 * i + 1).unwrap().clone();
                cmux(&mut ct_0, &mut ct_1, ggsw, buffers);
                vec_rlwe[i] = ct_0.clone();
            }
            vec_rlwe.truncate(vec_rlwe.len() / 2);
        }
    } else {
        let mut mask_and_body = vec![Scalar::ZERO; lut.len() * glwe_dimension.0]; //TODO
                                                                                  // error for GLWE
        mask_and_body.append(&mut lut.to_vec());
        let rlwe_lut = GlweCiphertext::from_container(mask_and_body, PolynomialSize(lut.len()));
        vec_rlwe.push(rlwe_lut);
    }
    vec_rlwe[0].clone()
}

pub fn cmux_tree_memory_optimized<Scalar>(
    lut: Vec<Scalar>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
    glwe_dimension: GlweDimension,
) -> GlweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    if !vec_ggsw.is_empty() {
        let polynomial_size = vec_ggsw[0].polynomial_size();
        let nb_layer = vec_ggsw.len();
        let mask_and_body = vec![Scalar::ZERO; polynomial_size.0 * (glwe_dimension.0 + 1)];

        let mut vec_lut = vec![];
        for ith_lut in lut.chunks(polynomial_size.0).into_iter() {
            vec_lut.push(ith_lut)
        }
        let mut result = GlweCiphertext::from_container(mask_and_body.clone(), polynomial_size);
        let rlwe_lut = GlweCiphertext::from_container(mask_and_body.clone(), polynomial_size);
        let mut t_0 = vec![rlwe_lut.clone(); nb_layer];
        let mut t_1 = vec![rlwe_lut; nb_layer];
        let mut t_fill = vec![0_usize; nb_layer];
        let mut cmux_buffer = GlweCiphertext::from_container(mask_and_body, polynomial_size);
        for i in 0..1 << (nb_layer - 1) {
            //load 2 trivial CT with LUT
            for (coef_0, lut_coef) in t_0[0]
                .get_mut_body()
                .as_mut_polynomial()
                .coefficient_iter_mut()
                .zip((vec_lut[2 * i]).iter())
            {
                //
                *coef_0 = *lut_coef;
            }
            for (coef_1, lut_coef) in t_1[0]
                .get_mut_body()
                .as_mut_polynomial()
                .coefficient_iter_mut()
                .zip((vec_lut[2 * i + 1]).iter())
            {
                //
                *coef_1 = *lut_coef;
            }
            t_fill[0] = 2;
            for (j, ggsw) in vec_ggsw.iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    if j != nb_layer - 1 {
                        if t_fill[j + 1] == 0_usize {
                            cmux_with_output(
                                &t_0[j].clone(),
                                &t_1[j],
                                &mut t_0[j + 1],
                                &mut cmux_buffer,
                                ggsw,
                                buffers,
                            );
                        } else {
                            cmux_with_output(
                                &t_0[j],
                                &t_1[j].clone(),
                                &mut t_1[j + 1],
                                &mut cmux_buffer,
                                ggsw,
                                buffers,
                            );
                        }
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;
                    } else {
                        cmux_with_output(
                            &t_0[j].clone(),
                            &t_1[j],
                            &mut result,
                            &mut cmux_buffer,
                            ggsw,
                            buffers,
                        );
                    }
                } else {
                    break;
                }
            }
        }

        result
    } else {
        let mut mask_and_body = vec![Scalar::ZERO; lut.len() * glwe_dimension.0];
        mask_and_body.append(&mut lut.to_vec());
        let rlwe_lut = GlweCiphertext::from_container(mask_and_body, PolynomialSize(lut.len()));
        rlwe_lut
    }
}

//return ct0 in ct0 if we have ggsw(0)
//return ct1 in ct0 if we have ggsw(1)
pub fn cmux<C0, C1, C2, Scalar>(
    ct_0: &mut GlweCiphertext<C0>,
    ct_1: &mut GlweCiphertext<C1>,
    ggsw: &FourierGgswCiphertext<C2, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
) where
    GlweCiphertext<C0>: AsMutTensor<Element = Scalar>,
    GlweCiphertext<C1>: AsMutTensor<Element = Scalar>,
    FourierGgswCiphertext<C2, Scalar>: AsRefTensor<Element = Complex64>,
    Scalar: UnsignedTorus,
{
    ct_1.as_mut_tensor()
        .update_with_wrapping_sub(ct_0.as_tensor());
    ggsw.external_product(ct_0, ct_1, buffers);
}

pub fn cmux_with_output<C0, C1, C2, C3, C4, Scalar>(
    ct_0: &GlweCiphertext<C0>,
    ct_1: &GlweCiphertext<C1>,
    ct_output: &mut GlweCiphertext<C2>,
    ct_buffer: &mut GlweCiphertext<C4>,
    ggsw: &FourierGgswCiphertext<C3, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
) where
    GlweCiphertext<C0>: AsMutTensor<Element = Scalar>,
    GlweCiphertext<C1>: AsMutTensor<Element = Scalar>,
    GlweCiphertext<C2>: AsMutTensor<Element = Scalar>,
    GlweCiphertext<C4>: AsMutTensor<Element = Scalar>,
    FourierGgswCiphertext<C3, Scalar>: AsRefTensor<Element = Complex64>,
    Scalar: UnsignedTorus,
{
    ct_buffer
        .as_mut_tensor()
        .fill_with_wrapping_sub(ct_1.as_tensor(), ct_0.as_tensor());
    ct_output.as_mut_tensor().fill_with(|| Scalar::ZERO);
    ggsw.external_product(ct_output, ct_buffer, buffers);
    ct_output
        .as_mut_tensor()
        .update_with_wrapping_add(ct_0.as_tensor())
}

pub fn blind_rotate<Scalar>(
    lut: &mut GlweCiphertext<Vec<Scalar>>,
    vec_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    buffers: &mut FourierBuffers<Scalar>,
) where
    Scalar: UnsignedTorus,
{
    let mut monomial_degree = MonomialDegree(1);
    let mut ct_0 = lut.clone();
    let mut ct_1 = GlweCiphertext::allocate(Scalar::ZERO, ct_0.polynomial_size(), ct_0.size());
    for ggsw in vec_ggsw.iter().rev() {
        ct_1.as_mut_tensor()
            .as_mut_slice()
            .copy_from_slice(ct_0.as_tensor().as_slice());

        ct_1.as_mut_polynomial_list()
            .update_with_wrapping_monic_monomial_div(monomial_degree);
        monomial_degree.0 <<= 1;
        cmux(&mut ct_0, &mut ct_1, ggsw, buffers);
    }

    lut.as_mut_tensor()
        .as_mut_slice()
        .copy_from_slice(ct_0.as_tensor().as_slice());
}

///////////////////////////////// need to be move in WOP_PBS_VP  ///////////////////////////////////
// CBS + VP
// CBS use PFKSK
pub fn vertical_packing_cbs_v0<Scalar>(
    vec_lut: Vec<Vec<Scalar>>,
    buffers: &mut FourierBuffers<Scalar>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    vec_lwe_in: &[LweCiphertext<Vec<Scalar>>],
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    vec_delta_log: Vec<DeltaLog>,
    vec_fpksk: &[FunctionalPackingKeyswitchKey<Vec<Scalar>>],
    vec_nb_bit_to_extract: Vec<usize>,
) -> Vec<LweCiphertext<Vec<Scalar>>>
where
    Scalar: UnsignedTorus + concrete_commons::numeric::CastFrom<i64>,
{
    let mut vec_ggsw = vec![];
    for i in 0..vec_lwe_in.len() {
        for j in (0..vec_nb_bit_to_extract[i]).rev() {
            let res = circuit_bootstrap(
                fourier_bsk,
                &vec_lwe_in[i],
                buffers,
                level_cbs,
                base_log_cbs,
                vec_delta_log[i],
                |x| (x & (1 << j)) >> j,
                vec_fpksk,
            );
            let mut ggsw = FourierGgswCiphertext::allocate(
                Complex64::new(0., 0.),
                fourier_bsk.polynomial_size(),
                fourier_bsk.glwe_size(),
                level_cbs,
                base_log_cbs,
            );
            FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &res, buffers);
            vec_ggsw.push(ggsw);
        }
    }
    let mut vec_res = vec![];
    for lut in vec_lut.iter() {
        let res = vertical_packing(lut.to_vec(), &vec_ggsw, buffers);
        vec_res.push(res);
    }
    vec_res
}

// CBS + VP
// CBS use ksk + external product
pub fn vertical_packing_cbs_v1<Scalar>(
    vec_lut: Vec<Vec<Scalar>>,
    buffers: &mut FourierBuffers<Scalar>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    vec_lwe_in: &[LweCiphertext<Vec<Scalar>>],
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    vec_delta_log: Vec<DeltaLog>,
    vec_nb_bit_to_extract: Vec<usize>,
    vec_fourier_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    pksk: &PackingKeyswitchKey<Vec<Scalar>>,
) -> Vec<LweCiphertext<Vec<Scalar>>>
where
    Scalar: UnsignedTorus + concrete_commons::numeric::CastFrom<i64>,
{
    let mut vec_ggsw = vec![];
    for i in 0..vec_lwe_in.len() {
        for j in (0..vec_nb_bit_to_extract[i]).rev() {
            let res = circuit_bootstrap_v1(
                fourier_bsk,
                &vec_lwe_in[i],
                buffers,
                level_cbs,
                base_log_cbs,
                vec_delta_log[i],
                |x| (x & (1 << j)) >> j,
                vec_fourier_ggsw,
                pksk,
            );
            let mut ggsw = FourierGgswCiphertext::allocate(
                Complex64::new(0., 0.),
                fourier_bsk.polynomial_size(),
                fourier_bsk.glwe_size(),
                level_cbs,
                base_log_cbs,
            );
            FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &res, buffers);
            vec_ggsw.push(ggsw);
        }
    }
    let mut vec_res = vec![];
    for lut in vec_lut.iter() {
        let res = vertical_packing(lut.to_vec(), &vec_ggsw, buffers);
        vec_res.push(res);
    }
    vec_res
}

// CBS + VP
// CBS use PFKSK
// for LWE with only one message bit
pub fn vertical_packing_cbs_binary<Scalar>(
    vec_lut: Vec<Vec<Scalar>>,
    buffers: &mut FourierBuffers<Scalar>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    vec_lwe_in: &[LweCiphertext<Vec<Scalar>>],
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    vec_delta_log: Vec<DeltaLog>,
    vec_fpksk: &[FunctionalPackingKeyswitchKey<Vec<Scalar>>],
) -> Vec<LweCiphertext<Vec<Scalar>>>
where
    Scalar: UnsignedTorus,
{
    let mut vec_ggsw = vec![];
    for i in 0..vec_lwe_in.len() {
        let res = circuit_bootstrap_binary(
            fourier_bsk,
            &vec_lwe_in[i],
            buffers,
            level_cbs,
            base_log_cbs,
            vec_delta_log[i],
            vec_fpksk,
        );
        let mut ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            fourier_bsk.polynomial_size(),
            fourier_bsk.glwe_size(),
            level_cbs,
            base_log_cbs,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &res, buffers);
        vec_ggsw.push(ggsw);
    }
    let mut vec_res = vec![];
    for lut in vec_lut.iter() {
        let res = vertical_packing(lut.to_vec(), &vec_ggsw, buffers);
        vec_res.push(res);
    }
    vec_res
}

// CBS + VP
// CBS use PFKSK
// for LWE with only one message bit
pub fn vertical_packing_cbs_binary_v0<Scalar>(
    vec_lut: Vec<Vec<Scalar>>,
    buffers: &mut FourierBuffers<Scalar>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    vec_lwe_in: &[LweCiphertext<Vec<Scalar>>],
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    vec_fpksk: &[FunctionalPackingKeyswitchKey<Vec<Scalar>>],
) -> Vec<LweCiphertext<Vec<Scalar>>>
where
    Scalar: UnsignedTorus,
{
    let mut vec_ggsw = vec![];
    for i in 0..vec_lwe_in.len() {
        let res = circuit_bootstrap_binary(
            fourier_bsk,
            &vec_lwe_in[i],
            buffers,
            level_cbs,
            base_log_cbs,
            DeltaLog(Scalar::BITS - 1),
            vec_fpksk,
        );
        let mut ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            fourier_bsk.polynomial_size(),
            fourier_bsk.glwe_size(),
            level_cbs,
            base_log_cbs,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &res, buffers);
        vec_ggsw.push(ggsw);
    }
    let mut vec_res = vec![];
    for lut in vec_lut.iter() {
        let res = vertical_packing(lut.to_vec(), &vec_ggsw, buffers);
        vec_res.push(res);
    }
    vec_res
}

// CBS + VP
// CBS use ksk + external product
// for LWE with only one message bit
pub fn vertical_packing_cbs_binary_v1<Scalar>(
    vec_lut: Vec<Vec<Scalar>>,
    buffers: &mut FourierBuffers<Scalar>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    vec_lwe_in: &[LweCiphertext<Vec<Scalar>>],
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    vec_fourier_ggsw: &[FourierGgswCiphertext<AlignedVec<Complex64>, Scalar>],
    pksk: &PackingKeyswitchKey<Vec<Scalar>>,
) -> Vec<LweCiphertext<Vec<Scalar>>>
where
    Scalar: UnsignedTorus + concrete_commons::numeric::CastFrom<i64>,
{
    let mut vec_ggsw = vec![];
    for i in 0..vec_lwe_in.len() {
        let res = circuit_bootstrap_binary_v1(
            fourier_bsk,
            &vec_lwe_in[i],
            buffers,
            level_cbs,
            base_log_cbs,
            DeltaLog(Scalar::BITS - 1),
            vec_fourier_ggsw,
            pksk,
        );
        let mut ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            fourier_bsk.polynomial_size(),
            fourier_bsk.glwe_size(),
            level_cbs,
            base_log_cbs,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &res, buffers);
        vec_ggsw.push(ggsw);
    }
    let mut vec_res = vec![];
    for lut in vec_lut.iter() {
        let res = vertical_packing(lut.to_vec(), &vec_ggsw, buffers);
        vec_res.push(res);
    }
    vec_res
}
