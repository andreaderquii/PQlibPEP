use crate::algebra::ring::{round_poly, PolyRq};

/// RLWR synthesizer from BPR12.
///
/// Computes:
///     S_{R,q,p}(x, y) = round_p(x * y)
///
/// where the multiplication is performed in
/// R_q = Z_q[X] / (X^n + 1), and the result is
/// rounded coefficient-wise into R_p.
pub fn synthesize(x: &PolyRq, y: &PolyRq, p: u64) -> PolyRq {
    assert_eq!(
        x.modulus(),
        y.modulus(),
        "RLWR inputs must have the same modulus"
    );

    assert_eq!(
        x.degree_bound(),
        y.degree_bound(),
        "RLWR inputs must have the same degree bound"
    );

    let product = x.mul_negacyclic(y);

    round_poly(&product, p)
}