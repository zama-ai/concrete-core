use crate::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// A structure to represent values in Z_q
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Debug, Default)]
pub struct ModQ<N: UnsignedInteger> {
    val: N,
    q: N,
}

/// Implement the ring operations in Z_q for ModQ
impl<N: UnsignedInteger> Add<Self> for ModQ<N> {
    type Output = ModQ<N>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.q.cast_into(), rhs.q.cast_into(), "Different Moduli!");
        debug_assert_ne!(self.q.cast_into(), N::ZERO.cast_into(), "Modulus is 0!");
        ModQ {
            val: (self.val + rhs.val) % self.q,
            q: self.q,
        }
    }
}

impl<N: UnsignedInteger> AddAssign<Self> for ModQ<N> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<N: UnsignedInteger> Mul<Self> for ModQ<N> {
    type Output = ModQ<N>;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.q.cast_into(), rhs.q.cast_into(), "Different Moduli!");
        debug_assert_ne!(self.q.cast_into(), N::ZERO.cast_into(), "Modulus is 0!");
        ModQ {
            val: (self.val * rhs.val) % self.q,
            q: self.q,
        }
    }
}

impl<N: UnsignedInteger> MulAssign<Self> for ModQ<N> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<N: UnsignedInteger> Neg for ModQ<N> {
    type Output = ModQ<N>;

    fn neg(self) -> Self::Output {
        debug_assert_ne!(self.q.cast_into(), N::ZERO.cast_into(), "Modulus is 0!");
        ModQ {
            val: (self.q - self.val) % self.q,
            q: self.q,
        }
    }
}

impl<N: UnsignedInteger> Sub<Self> for ModQ<N> {
    type Output = ModQ<N>;

    fn sub(self, rhs: Self) -> Self::Output {
        ModQ {
            val: (self + (-rhs)).val % self.q,
            q: self.q,
        }
    }
}

impl<N: UnsignedInteger> SubAssign<Self> for ModQ<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<Element: UnsignedInteger> ModQ<Element> {
    /// scales the stored value to a new modulus (a power of two)
    /// implicitly specified by the type N
    pub fn mod_switch_from<N: UnsignedInteger + CastFrom<Element>>(self) -> N {
        let new_val = ((self.val << N::BITS) | (self.q >> 1)) / self.q;
        N::cast_from(new_val)
    }

    /// scales the given value, interpreted as a value mod a power of two
    /// implicitly specified by the type N, to the modulus self.q
    pub fn mod_switch_into<N: UnsignedInteger + CastInto<Element>>(&mut self, input: N) {
        let new_val: Element = <N as CastInto<Element>>::cast_into(input);
        self.set((new_val * self.q + (Element::ONE << (N::BITS - 1))) >> N::BITS);
    }

    pub fn set(&mut self, input: Element) {
        debug_assert_ne!(
            self.q.cast_into(),
            Element::ZERO.cast_into(),
            "Modulus is 0!"
        );
        self.val = input % self.q;
    }

    pub fn get(self) -> Element {
        self.val
    }

    pub fn get_mod(self) -> Element {
        self.q
    }

    pub fn new(val: Element, q: Element) -> Self {
        // for 0 modulus use empty
        debug_assert_ne!(q.cast_into(), Element::ZERO.cast_into(), "Modulus is 0!");
        ModQ { val: val % q, q }
    }

    pub fn empty() -> Self {
        ModQ {
            val: Element::ZERO,
            q: Element::ZERO,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::backends::ntt::private::math::params::params_64_128::MOD_64_128;

    fn test_add_modq<N: UnsignedInteger + Debug>() {
        let q: N = N::cast_from(255.);
        let a: ModQ<N> = ModQ::new(N::cast_from(100.), q);
        let b: ModQ<N> = ModQ::new(N::cast_from(200.), q);

        assert_eq!((a + b).val, N::cast_from(45.));
    }

    #[test]
    fn test_add_modq_64() {
        test_add_modq::<u64>();
    }

    #[test]
    fn test_add_modq_128() {
        test_add_modq::<u128>();
    }

    fn test_sub_modq<N: UnsignedInteger + Debug>() {
        let q: N = N::cast_from(255.);
        let a: ModQ<N> = ModQ::new(N::cast_from(100.), q);
        let b: ModQ<N> = ModQ::new(N::cast_from(200.), q);

        assert_eq!((a - b).val, N::cast_from(155.));
    }

    #[test]
    fn test_sub_modq_64() {
        test_sub_modq::<u64>();
    }

    #[test]
    fn test_sub_modq_128() {
        test_sub_modq::<u128>();
    }

    fn test_mul_modq<N: UnsignedInteger + Debug>() {
        let q: N = N::cast_from(255.);
        let a: ModQ<N> = ModQ::new(N::cast_from(100.), q);
        let b: ModQ<N> = ModQ::new(N::cast_from(200.), q);

        assert_eq!((a * b).val, N::cast_from(110.));
    }

    #[test]
    fn test_mul_modq_64() {
        test_mul_modq::<u64>();
    }

    #[test]
    fn test_mul_modq_128() {
        test_mul_modq::<u128>();
    }

    fn test_switch_modq<
        N: UnsignedInteger + Debug,
        N1: UnsignedInteger + CastFrom<N> + CastInto<N>,
    >() {
        let q: N = N::cast_from(256.);
        let a: ModQ<N> = ModQ::new(N::cast_from(128.), q);
        let b: N1 = a.mod_switch_from();
        let mut c: ModQ<N> = ModQ::new(N::cast_from(0.), q);
        c.mod_switch_into(b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_switch_modq_64() {
        test_switch_modq::<u64, u32>();
    }

    #[test]
    fn test_switch_modq_128() {
        test_switch_modq::<u128, u64>();
    }

    #[test]
    fn test_switch_modq_64_2() {
        let q: u128 = MOD_64_128;
        let a: u64 = 17723707332261611143;
        let mut b: ModQ<u128> = ModQ::new(0u128, q);
        b.mod_switch_into(a);
        assert_eq!(b.get(), 17723707332261500951u128);
    }

    #[test]
    fn test_switch_modq_64_3() {
        let q: u128 = MOD_64_128;
        let a: ModQ<u128> = ModQ::new(17723707332261611143u128, q);
        let b: u64 = a.mod_switch_from();
        assert_eq!(b, 17723707332261721335u64);
    }
}
