pub fn update_with_wrapping_unit_monomial_div(polynomial: &mut [u64], monomial_degree: usize) {
    let full_cycles_count = monomial_degree / polynomial.len();
    if full_cycles_count % 2 != 0 {
        polynomial.iter_mut().for_each(|a| *a = a.wrapping_neg());
    }
    let remaining_degree = monomial_degree % polynomial.len();
    polynomial.rotate_left(remaining_degree);
    polynomial
        .iter_mut()
        .rev()
        .take(remaining_degree)
        .for_each(|a| *a = a.wrapping_neg());
}

pub fn update_with_wrapping_monic_monomial_mul(polynomial: &mut [u64], monomial_degree: usize) {
    let full_cycles_count = monomial_degree / polynomial.len();
    if full_cycles_count % 2 != 0 {
        polynomial.iter_mut().for_each(|a| *a = a.wrapping_neg());
    }
    let remaining_degree = monomial_degree % polynomial.len();
    polynomial.rotate_right(remaining_degree);
    polynomial
        .iter_mut()
        .take(remaining_degree)
        .for_each(|a| *a = a.wrapping_neg());
}
