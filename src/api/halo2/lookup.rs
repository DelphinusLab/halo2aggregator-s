use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Expression;

#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) input_expressions: Vec<Expression<AstScalar<C>>>,
    pub(crate) table_expressions: Vec<Expression<AstScalar<C>>>,
    pub(crate) product_eval: AstScalar<C>,
    pub(crate) product_next_eval: AstScalar<C>,
    pub(crate) permuted_input_eval: AstScalar<C>,
    pub(crate) permuted_input_inv_eval: AstScalar<C>,
    pub(crate) permuted_table_eval: AstScalar<C>,

    pub(crate) permuted_input_commitment: AstPoint<C>,
    pub(crate) permuted_table_commitment: AstPoint<C>,
    pub(crate) product_commitment: AstPoint<C>,
}
