use concrete_core::backends::fft::private::math::fft::Fft as FftImpl;

#[repr(transparent)]
pub struct Csprng {
    __private: (),
}

#[repr(transparent)]
pub struct Fft {
    pub(crate) inner: FftImpl,
}

#[repr(u32)]
pub enum ScratchStatus {
    Valid = 0,
    SizeOverflow = 1,
}

#[repr(u32)]
pub enum Parallelism {
    No = 0,
    Rayon = 1,
}
