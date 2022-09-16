pub mod mod_q;
pub mod params;
pub mod polynomial;
pub mod transform;

pub(crate) const ALLOWED_POLY_SIZE: [usize; 6] = [128, 256, 512, 1024, 2048, 4096];
