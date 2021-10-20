use std::ffi::c_void;

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct StreamPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CudaLweCiphertextVectorPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CudaGlweCiphertextVectorPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CudaLweCiphertextPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CudaGlweCiphertextPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CudaBootstrapKeyPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CpuBootstrapKeyPointer(pub *mut c_void);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CudaLweKeyswitchKeyPointer(pub *mut c_void);
