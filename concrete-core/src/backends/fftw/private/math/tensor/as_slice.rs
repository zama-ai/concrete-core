use concrete_fftw::array::AlignedVec;
use crate::commons::math::tensor::{AsMutSlice, AsRefSlice};

impl<Element> AsRefSlice for AlignedVec<Element> {
    type Element = Element;
    fn as_slice(&self) -> &[Element] {
        self.as_slice()
    }
}

impl<Element> AsMutSlice for AlignedVec<Element> {
    type Element = Element;
    fn as_mut_slice(&mut self) -> &mut [Element] {
        self.as_slice_mut()
    }
}
