use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use halo2_proofs::arithmetic::CurveAffine;

#[derive(Debug)]
pub struct CommonEvaluated<C: CurveAffine> {
    pub key: String,
    pub permutation_evals: Vec<AstScalar<C>>,
    pub permutation_commitments: Vec<AstPoint<C>>,
}

#[derive(Debug)]
pub struct EvaluatedSet<C: CurveAffine> {
    pub(crate) permutation_product_commitment: AstPoint<C>,
    pub(crate) permutation_product_eval: AstScalar<C>,
    pub(crate) permutation_product_next_eval: AstScalar<C>,
    pub(crate) permutation_product_last_eval: Option<AstScalar<C>>,
}

#[derive(Debug)]
pub struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) blinding_factors: usize,
    pub(crate) x: AstScalar<C>,
    pub(crate) sets: Vec<EvaluatedSet<C>>,
    pub(crate) evals: Vec<AstScalar<C>>,
    pub(crate) chunk_len: usize,
}
