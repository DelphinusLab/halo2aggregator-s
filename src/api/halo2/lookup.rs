use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Expression;
use std::rc::Rc;

#[derive(Debug)]
pub struct PermutationCommitments<C: CurveAffine> {
    pub(crate) permuted_input_commitment: Rc<AstPoint<C>>,
    pub(crate) permuted_table_commitment: Rc<AstPoint<C>>,
}

#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) input_expressions: Vec<Expression<AstScalar<C>>>,
    pub(crate) table_expressions: Vec<Expression<AstScalar<C>>>,
    pub(crate) product_eval: Rc<AstScalar<C>>,
    pub(crate) product_next_eval: Rc<AstScalar<C>>,
    pub(crate) permuted_input_eval: Rc<AstScalar<C>>,
    pub(crate) permuted_input_inv_eval: Rc<AstScalar<C>>,
    pub(crate) permuted_table_eval: Rc<AstScalar<C>>,

    pub(crate) permuted_commitment: PermutationCommitments<C>,
    pub(crate) product_commitment: Rc<AstPoint<C>>,
}
