use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::crypto::circuit_bootstrap::DeltaLog;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::commons::crypto::encoding::{Cleartext, PlaintextList};
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use crate::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::commons::crypto::secret::GlweSecretKey;
use crate::commons::math::polynomial::Polynomial;
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweSize};
use concrete_fftw::array::AlignedVec;
#[cfg(test)]
mod test;

use crate::commons::math::random::ByteRandomGenerator;

pub fn create_ggsw<GLWEKeyCont, Scalar, G>(
    level_ext: DecompositionLevelCount,
    base_log_ext: DecompositionBaseLog,
    glwe_key: &GlweSecretKey<BinaryKeyKind, GLWEKeyCont>,
    std: LogStandardDev,
    mut encryption_generator: &mut EncryptionRandomGenerator<G>,
) -> Vec<StandardGgswCiphertext<Vec<Scalar>>>
where
    GlweSecretKey<BinaryKeyKind, GLWEKeyCont>: AsRefTensor<Element = Scalar>,
    Scalar: UnsignedTorus,
    G: ByteRandomGenerator,
{
    let glwe_dimension = glwe_key.key_size().to_glwe_size().to_glwe_dimension();
    let mut glwe_out = GlweCiphertext::allocate(
        Scalar::ZERO,
        glwe_key.polynomial_size(),
        glwe_key.key_size().to_glwe_size(),
    );
    let mut vec_ggsw = vec![];
    for i in 0..glwe_dimension.0 {
        let mut vec_tensor = vec![];
        for j in 1..=level_ext.0 {
            for k in 0..glwe_dimension.0 {
                glwe_out.as_mut_tensor().fill_with(|| Scalar::ZERO);
                let mut vec = vec![Scalar::ZERO; glwe_out.polynomial_size().0];
                let mut polynomial_out =
                    Polynomial::from_container(vec![Scalar::ZERO; glwe_out.polynomial_size().0]);
                let mut polynomial_out2 =
                    Polynomial::from_container(vec![Scalar::ZERO; glwe_out.polynomial_size().0]);
                vec[0] = Scalar::ONE << (64 - base_log_ext.0 * j);

                // polynomial with S_i * 1<<(modulus - beta * level )
                polynomial_out.update_with_wrapping_add_mul(
                    &glwe_key.as_polynomial_list().get_polynomial(i),
                    &Polynomial::from_container(vec),
                );

                // polynomial with S_k * S_i * 1<<(modulus - beta * level )
                polynomial_out2.update_with_wrapping_add_mul(
                    &glwe_key.as_polynomial_list().get_polynomial(k),
                    &polynomial_out,
                );
                let encoded = PlaintextList::from_container(polynomial_out2.tensor);

                //encrypt polynomial S_k * S_i * 1<<(modulus - beta * level )
                glwe_key.encrypt_glwe(&mut glwe_out, &encoded, std, &mut encryption_generator);
                let tmp_tensor = glwe_out.tensor.as_container();
                vec_tensor.append(&mut tmp_tensor.to_vec());
            }

            glwe_out.as_mut_tensor().fill_with(|| Scalar::ZERO);
            let mut vec = vec![Scalar::ZERO; glwe_out.polynomial_size().0];
            let mut polynomial_out =
                Polynomial::from_container(vec![Scalar::ZERO; glwe_out.polynomial_size().0]);
            vec[0] = Scalar::ONE << (64 - base_log_ext.0 * j);
            // polynomial with  -S_i * 1<<(modulus - beta * level )
            polynomial_out.update_with_wrapping_sub_mul(
                &glwe_key.as_polynomial_list().get_polynomial(i),
                &Polynomial::from_container(vec),
            );
            let encoded = PlaintextList::from_container(polynomial_out.tensor);

            //encrypt polynomial - S_i * 1<<(modulus - beta * level )
            glwe_key.encrypt_glwe(&mut glwe_out, &encoded, std, &mut encryption_generator);
            let tmp_tensor = glwe_out.tensor.as_container();
            vec_tensor.append(&mut tmp_tensor.to_vec());
        }
        let ggsw = StandardGgswCiphertext::from_container(
            vec_tensor.clone(),
            glwe_key.key_size().to_glwe_size(),
            glwe_key.polynomial_size(),
            base_log_ext,
        );

        vec_ggsw.push(ggsw);
    }
    vec_ggsw
}

// Extract one bit of a LWE
// and return LWE(Alpha_i << (Delta + i))
pub fn extract_bit<Scalar>(
    delta_log: DeltaLog,
    lwe_in: &mut LweCiphertext<Vec<Scalar>>,
    ksk: &LweKeyswitchKey<Vec<Scalar>>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
    number_values_to_extract: usize,
) -> (Vec<LweCiphertext<Vec<Scalar>>>, Vec<DeltaLog>)
where
    Scalar: UnsignedTorus,
{
    let modulus_size = Scalar::BITS;
    if modulus_size - delta_log.0 < number_values_to_extract {
        panic!();
    }
    let mut loops_number = number_values_to_extract;
    if modulus_size - number_values_to_extract - delta_log.0 == 0 {
        loops_number -= 1;
    }

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let lwe_in_size = lwe_in.lwe_size();
    //output
    let mut vec_lwe_out = vec![];
    let mut vec_delta_out = vec![];

    for i in 0..loops_number {
        let mut lwe_out_bs = LweCiphertext::allocate(
            Scalar::ZERO,
            LweSize((glwe_size.0 - 1) * polynomial_size.0 + 1),
        );

        //shift on padding bit
        let mut lwe_tmp = LweCiphertext::allocate(Scalar::ZERO, lwe_in_size);
        lwe_tmp.fill_with_scalar_mul(
            lwe_in,
            &Cleartext(Scalar::ONE << (modulus_size - delta_log.0 - i - 1)),
        );

        //add q/4
        let mut cont = vec![Scalar::ZERO; lwe_in_size.0];
        cont[lwe_in_size.0 - 1] = Scalar::ONE << (modulus_size - 2);
        let tmp = LweCiphertext::from_container(cont);
        lwe_tmp.update_with_add(&tmp);

        //key switch
        let mut lwe_out_ks = LweCiphertext::allocate(Scalar::ZERO, ksk.lwe_size());
        ksk.keyswitch_ciphertext(&mut lwe_out_ks, &lwe_tmp);

        //lut creation
        let mut look_up_table = vec![Scalar::ZERO; polynomial_size.0 * (glwe_size.0 - 1)];
        look_up_table.append(&mut vec![
            Scalar::ZERO.wrapping_sub(
                Scalar::ONE << (delta_log.0 - 1 + i)
            );
            polynomial_size.0
        ]);
        let accumulator = GlweCiphertext::from_container(look_up_table, polynomial_size);

        //pbs
        fourier_bsk.bootstrap(&mut lwe_out_bs, &lwe_out_ks, &accumulator, buffers);

        //add delta_log-1
        let mut cont = vec![Scalar::ZERO; polynomial_size.0 + 1];
        cont[polynomial_size.0] = Scalar::ONE << (delta_log.0 - 1 + i);
        let tmp = LweCiphertext::from_container(cont);
        lwe_out_bs.update_with_add(&tmp);

        //sub the result to the first LWE
        lwe_in.update_with_sub(&lwe_out_bs.clone());

        //store the output
        vec_lwe_out.push(lwe_out_bs);
        vec_delta_out.push(DeltaLog(delta_log.0 + i));
    }
    if loops_number != number_values_to_extract {
        vec_lwe_out.push(lwe_in.clone());
        vec_delta_out.push(DeltaLog(modulus_size - 1));
    }
    (vec_lwe_out, vec_delta_out)
}

// Extract one bit of a LWE
// and return LWE(Alpha_i << (modulus -1))
pub fn extract_bit_v0_v1<Scalar>(
    delta_log: DeltaLog,
    lwe_in: &mut LweCiphertext<Vec<Scalar>>,
    ksk: &LweKeyswitchKey<Vec<Scalar>>,
    fourier_bsk: &FourierBootstrapKey<AlignedVec<Complex64>, Scalar>,
    buffers: &mut FourierBuffers<Scalar>,
    number_values_to_extract: usize,
) -> Vec<LweCiphertext<Vec<Scalar>>>
where
    Scalar: UnsignedTorus,
{
    let modulus_size = Scalar::BITS;
    if modulus_size - delta_log.0 < number_values_to_extract {
        panic!();
    }
    let mut loops_number = number_values_to_extract;
    if modulus_size - number_values_to_extract - delta_log.0 == 0 {
        loops_number -= 1;
    }

    //TODO
    let mut bool = 0;
    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let lwe_in_size = lwe_in.lwe_size();

    //output
    let mut vec_lwe_out = vec![];

    for i in 0..loops_number {
        let mut lwe_out_bs = LweCiphertext::allocate(
            Scalar::ZERO,
            LweSize((glwe_size.0 - 1) * polynomial_size.0 + 1),
        );

        //shift on padding bit
        let mut lwe_tmp = LweCiphertext::allocate(Scalar::ZERO, lwe_in_size);
        lwe_tmp.fill_with_scalar_mul(
            lwe_in,
            &Cleartext(Scalar::ONE << (modulus_size - delta_log.0 - i - 1)),
        );

        //key switch
        let mut lwe_out_ks = LweCiphertext::allocate(Scalar::ZERO, ksk.lwe_size());
        ksk.keyswitch_ciphertext(&mut lwe_out_ks, &lwe_tmp);
        //store the output
        //TODO
        if bool != 0 {
            vec_lwe_out.push(lwe_out_ks.clone());
        }

        //add q/4
        let mut cont = vec![Scalar::ZERO; ksk.lwe_size().0];
        cont[ksk.lwe_size().0 - 1] = Scalar::ONE << (modulus_size - 2);
        let tmp = LweCiphertext::from_container(cont);
        lwe_out_ks.update_with_add(&tmp);

        //lut creation
        let mut look_up_table = vec![Scalar::ZERO; polynomial_size.0 * (glwe_size.0 - 1)];
        look_up_table.append(&mut vec![
            Scalar::ZERO.wrapping_sub(
                Scalar::ONE << (delta_log.0 - 1 + i)
            );
            polynomial_size.0
        ]);
        let accumulator = GlweCiphertext::from_container(look_up_table, polynomial_size);

        //pbs
        fourier_bsk.bootstrap(&mut lwe_out_bs, &lwe_out_ks, &accumulator, buffers);

        //add delta_log-1
        let mut cont = vec![Scalar::ZERO; polynomial_size.0 * (glwe_size.0 - 1) + 1];
        cont[polynomial_size.0 * (glwe_size.0 - 1)] = Scalar::ONE << (delta_log.0 - 1 + i);
        let tmp = LweCiphertext::from_container(cont);
        lwe_out_bs.update_with_add(&tmp);

        //TODO
        if bool == 0 {
            bool = 1;

            //shift on padding bit
            let mut lwe_tmp = LweCiphertext::allocate(Scalar::ZERO, lwe_in_size);
            lwe_tmp.fill_with_scalar_mul(
                &lwe_out_bs.clone(),
                &Cleartext(Scalar::ONE << (modulus_size - delta_log.0 - i - 1)),
            );

            //key switch
            let mut lwe_out_ks = LweCiphertext::allocate(Scalar::ZERO, ksk.lwe_size());
            ksk.keyswitch_ciphertext(&mut lwe_out_ks, &lwe_tmp);

            vec_lwe_out.push(lwe_out_ks);
        }

        //sub the result to the first LWE
        lwe_in.update_with_sub(&lwe_out_bs);
    }
    if loops_number != number_values_to_extract {
        let mut lwe_out_ks = LweCiphertext::allocate(Scalar::ZERO, ksk.lwe_size());
        ksk.keyswitch_ciphertext(&mut lwe_out_ks, &lwe_in);
        vec_lwe_out.push(lwe_out_ks);
    }
    vec_lwe_out
}
