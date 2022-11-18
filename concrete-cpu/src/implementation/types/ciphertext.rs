use crate::implementation::{Container, ContainerMut};

use super::LweDimension;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[readonly::make]
pub struct LweCiphertext<C: Container<Item = u64>> {
    pub data: C,
    pub lwe_dimension: LweDimension,
}

impl<C: Container<Item = u64>> LweCiphertext<C> {
    pub fn data_len(lwe_dimension: LweDimension) -> usize {
        lwe_dimension.as_lwe_size().0
    }

    pub fn new(data: C, lwe_dimension: LweDimension) -> Self {
        debug_assert_eq!(data.len(), Self::data_len(lwe_dimension));
        Self {
            data,
            lwe_dimension,
        }
    }

    pub fn as_view(&self) -> LweCiphertext<&[u64]> {
        LweCiphertext {
            data: self.data.as_ref(),
            lwe_dimension: self.lwe_dimension,
        }
    }

    pub fn as_mut_view(&mut self) -> LweCiphertext<&mut [u64]>
    where
        C: ContainerMut,
    {
        LweCiphertext {
            data: self.data.as_mut(),
            lwe_dimension: self.lwe_dimension,
        }
    }

    pub fn into_data(self) -> C {
        self.data
    }
}
