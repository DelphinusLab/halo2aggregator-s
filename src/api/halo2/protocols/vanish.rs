use super::super::query::EvaluationQuery;
use super::super::query::EvaluationQuerySchemaRc;
use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use crate::api::halo2::verifier::VerifierParams;
use crate::scalar;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

pub struct Evaluated<C: CurveAffine> {
    key: String,
    h_commitment: EvaluationQuerySchemaRc<C>,
    expected_h_eval: Rc<AstScalar<C>>,
    random_commitment: Rc<AstPoint<C>>,
    random_eval: Rc<AstScalar<C>>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub fn build_from_verifier_params(key: String, params: VerifierParams<C>) -> Self {
        todo!();
    }
}

impl<C: CurveAffine> Evaluated<C> {
    pub fn queries(&self, x: &Rc<AstScalar<C>>) -> Vec<EvaluationQuery<C>> {
        vec![
            EvaluationQuery::new_with_query(
                0,
                x.clone(),
                self.h_commitment.clone() + scalar!(self.expected_h_eval.clone()),
            ),
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_random_commitment", self.key),
                self.random_commitment.clone(),
                self.random_eval.clone(),
            ),
        ]
    }
}
