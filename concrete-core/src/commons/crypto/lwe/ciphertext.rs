use super::LweList;
use crate::commons::crypto::encoding::{Cleartext, CleartextList, Plaintext};
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::crypto::secret::LweSecretKey;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor, Tensor};
use crate::commons::math::torus::UnsignedTorus;
use concrete_commons::key_kinds::KeyKind;
use concrete_commons::numeric::{Numeric, UnsignedInteger};
use concrete_commons::parameters::{LweDimension, LweSize, MonomialDegree};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertext<T: UnsignedInteger> {
    pub(crate) tensor: Tensor<Vec<T>>,
}

impl<Scalar: UnsignedInteger> LweCiphertext<Scalar> {
    pub fn from_vec(v: Vec<Scalar>) -> Self {
        LweCiphertext {
            tensor: Tensor::from_container(v),
        }
    }

    pub fn to_vec(self) -> Vec<Scalar> {
        self.tensor.into_container()
    }

    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.tensor.len())
    }

    pub fn allocate(value: Scalar, size: LweSize) -> Self {
        LweCiphertext {
            tensor: Tensor::from_container(vec![value; size.0]),
        }
    }

    pub fn new_trivial_encryption(lwe_size: LweSize, plaintext: &Plaintext<Scalar>) -> Self {
        let mut ciphertext = Self::allocate(Scalar::ZERO, lwe_size);
        ciphertext.as_mut().fill_with_trivial_encryption(plaintext);
        ciphertext
    }

    pub fn as_ref(&self) -> LweCiphertextView<Scalar> {
        LweCiphertextView {
            tensor: Tensor::from_container(self.tensor.as_container().as_slice()),
        }
    }

    pub fn as_mut(&mut self) -> LweCiphertextMutView<Scalar> {
        LweCiphertextMutView {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut_slice()),
        }
    }
}

#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextView<'a, T: UnsignedInteger> {
    pub(crate) tensor: Tensor<&'a [T]>,
}

impl<'a, Scalar: UnsignedInteger> LweCiphertextView<'a, Scalar> {
    pub fn from_slice(v: &'a [Scalar]) -> Self {
        LweCiphertextView {
            tensor: Tensor::from_container(v),
        }
    }

    pub fn to_slice(self) -> &'a [Scalar] {
        self.tensor.into_container()
    }

    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.tensor.len())
    }

    pub fn get_body(&self) -> &LweBody<Scalar> {
        unsafe { &*{ self.tensor.last() as *const Scalar as *const LweBody<Scalar> } }
    }

    pub fn get_mask(&self) -> LweMaskView<Scalar> {
        let (_, mask) = self.tensor.split_last();
        LweMaskView { tensor: mask }
    }

    pub fn get_body_and_mask(&self) -> (&LweBody<Scalar>, LweMaskView<Scalar>) {
        let (body, mask) = self.tensor.split_last();
        let body = unsafe { &*{ body as *const Scalar as *const LweBody<Scalar> } };
        (body, LweMaskView { tensor: mask })
    }
}

#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextMutView<'a, T: UnsignedInteger> {
    pub(crate) tensor: Tensor<&'a mut [T]>,
}

impl<'a, Scalar: UnsignedInteger> LweCiphertextMutView<'a, Scalar> {
    pub fn from_mut_slice(v: &'a mut [Scalar]) -> Self {
        LweCiphertextMutView {
            tensor: Tensor::from_container(v),
        }
    }

    pub fn to_mut_slice(self) -> &'a mut [Scalar] {
        self.tensor.into_container()
    }

    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.tensor.len())
    }

    pub fn as_ref(&self) -> LweCiphertextView<Scalar> {
        LweCiphertextView {
            tensor: Tensor::from_container(self.tensor.as_container()),
        }
    }

    pub fn get_mut_body(&mut self) -> &mut LweBody<Scalar> {
        unsafe { &mut *{ self.tensor.last_mut() as *mut Scalar as *mut LweBody<Scalar> } }
    }

    pub fn get_mut_mask(&mut self) -> LweMaskMutView<Scalar> {
        let (_, masks) = self.tensor.split_last_mut();
        LweMaskMutView { tensor: masks }
    }

    pub fn get_mut_body_and_mask(&mut self) -> (&mut LweBody<Scalar>, LweMaskMutView<Scalar>) {
        let (body, masks) = self.tensor.split_last_mut();
        let body = unsafe { &mut *{ body as *mut Scalar as *mut LweBody<Scalar> } };
        (body, LweMaskMutView { tensor: masks })
    }

    pub fn fill_with_scalar_mul(
        &mut self,
        input: &LweCiphertextView<Scalar>,
        scalar: &Cleartext<Scalar>,
    ) {
        self.tensor
            .fill_with_one(&input.tensor, |o| o.wrapping_mul(scalar.0));
    }

    pub fn fill_with_multisum_with_bias<InputCont, WeightCont>(
        &mut self,
        input_list: &LweList<InputCont>,
        weights: &CleartextList<WeightCont>,
        bias: &Plaintext<Scalar>,
    ) where
        LweList<InputCont>: AsRefTensor<Element = Scalar>,
        CleartextList<WeightCont>: AsRefTensor<Element = Scalar>,
    {
        // loop over the ciphertexts and the weights
        for (input_cipher, weight) in input_list.ciphertext_iter().zip(weights.cleartext_iter()) {
            let cipher_tens = &input_cipher.tensor;
            self.tensor.update_with_one(cipher_tens, |o, c| {
                *o = o.wrapping_add(c.wrapping_mul(weight.0))
            });
        }

        // add the bias
        let new_body = (self.as_ref().get_body().0).wrapping_add(bias.0);
        *self.get_mut_body() = LweBody(new_body);
    }

    pub fn update_with_add(&mut self, other: &LweCiphertextView<Scalar>) {
        self.tensor.update_with_wrapping_add(&other.tensor)
    }

    pub fn update_with_sub(&mut self, other: &LweCiphertextView<Scalar>) {
        self.tensor.update_with_wrapping_sub(&other.tensor)
    }

    pub fn update_with_neg(&mut self) {
        self.tensor.update_with_wrapping_neg()
    }

    pub fn update_with_scalar_mul(&mut self, scalar: Cleartext<Scalar>) {
        self.tensor.update_with_wrapping_scalar_mul(&scalar.0)
    }

    pub fn fill_with_trivial_encryption(&mut self, plaintext: &Plaintext<Scalar>) {
        let (output_body, mut output_mask) = self.get_mut_body_and_mask();

        // generate a uniformly random mask
        output_mask.tensor.fill_with_element(Scalar::ZERO);

        // No need to do the multisum between the secret key and the mask
        // as the mask only contains zeros

        // add the encoded message
        output_body.0 = plaintext.0;
    }
}

impl<'a, Scalar: UnsignedTorus> LweCiphertextMutView<'a, Scalar> {
    pub fn fill_with_glwe_sample_extraction<InputCont>(
        &mut self,
        glwe: &GlweCiphertext<InputCont>,
        n_th: MonomialDegree,
    ) where
        GlweCiphertext<InputCont>: AsRefTensor<Element = Scalar>,
    {
        glwe.fill_lwe_with_sample_extraction(self, n_th);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LweMask<Scalar: UnsignedInteger> {
    tensor: Tensor<Vec<Scalar>>,
}

impl<Scalar: UnsignedInteger> LweMask<Scalar> {
    pub fn from_vec(v: Vec<Scalar>) -> LweMask<Scalar> {
        LweMask {
            tensor: Tensor::from_container(v),
        }
    }

    pub fn as_ref(&self) -> LweMaskView<'_, Scalar> {
        LweMaskView {
            tensor: Tensor::from_container(self.tensor.as_container().as_slice()),
        }
    }

    pub fn as_mut(&mut self) -> LweMaskMutView<'_, Scalar> {
        LweMaskMutView {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut_slice()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LweMaskView<'a, Scalar: UnsignedInteger> {
    pub(crate) tensor: Tensor<&'a [Scalar]>,
}

impl<'a, Scalar: UnsignedInteger> LweMaskView<'a, Scalar> {
    pub fn mask_element_iter(&self) -> impl Iterator<Item = &Scalar> {
        self.tensor.iter()
    }

    pub fn mask_size(&self) -> LweDimension {
        LweDimension(self.tensor.len())
    }

    pub fn compute_multisum<Kind, Cont1>(&self, key: &LweSecretKey<Kind, Cont1>) -> Scalar
    where
        LweSecretKey<Kind, Cont1>: AsRefTensor<Element = Scalar>,
        Kind: KeyKind,
    {
        self.tensor.fold_with_one(
            key.as_tensor(),
            <Scalar as Numeric>::ZERO,
            |ac, s_i, o_i| ac.wrapping_add(*s_i * *o_i),
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LweMaskMutView<'a, Scalar: UnsignedInteger> {
    pub(crate) tensor: Tensor<&'a mut [Scalar]>,
}

impl<'a, Scalar: UnsignedInteger> LweMaskMutView<'a, Scalar> {
    pub fn from_mut_slice(c: &'a mut [Scalar]) -> LweMaskMutView<'a, Scalar> {
        LweMaskMutView {
            tensor: Tensor::from_container(c),
        }
    }

    pub fn as_ref(&'a self) -> LweMaskView<'a, Scalar> {
        LweMaskView {
            tensor: Tensor::from_container(self.tensor.as_container().as_slice()),
        }
    }

    pub fn mask_size(&self) -> LweDimension {
        LweDimension(self.tensor.len())
    }
    pub fn mask_element_iter_mut(&'a mut self) -> impl Iterator<Item = &'a mut Scalar> {
        self.tensor.iter_mut()
    }
}

/// The body of an Lwe ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct LweBody<T>(pub T);
