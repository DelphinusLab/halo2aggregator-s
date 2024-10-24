use super::super::query::EvaluationQuery;
use super::super::query::EvaluationQuerySchemaRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::api::halo2::query::CommitQuery;
use crate::api::halo2::verifier::VerifierParams;
use crate::commit;
use crate::scalar;
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use std::rc::Rc;

pub struct Evaluated<C: CurveAffine> {
    key: String,
    h_commitment: EvaluationQuerySchemaRc<C>,
    expected_h_eval: AstScalarRc<C>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub fn build_from_verifier_params(
        params: &VerifierParams<C>,
        expression_evals: Vec<AstScalarRc<C>>,
    ) -> Self {
        let one = &sconst!(C::ScalarExt::one());

        let expected_h_eval = expression_evals
            .into_iter()
            .reduce(|acc, x| acc * &params.y + x)
            .unwrap();
        let expected_h_eval = expected_h_eval / (&params.xn - one);

        let h_commitment = params
            .vanish_commitments
            .iter()
            .rev()
            .enumerate()
            .map(|(i, c)| {
                commit!(Rc::new(CommitQuery {
                    key: format!("{}_h_commitment{}", params.key.clone(), i),
                    commitment: Some(c.clone()),
                    eval: None,
                }))
            })
            .reduce(|acc, commitment| scalar!(params.xn.clone()) * acc + commitment)
            .unwrap();

        Evaluated {
            key: params.key.clone(),
            h_commitment,
            expected_h_eval,
        }
    }

    pub fn queries(&self, params: &VerifierParams<C>) -> Vec<EvaluationQuery<C>> {
        vec![
            EvaluationQuery::new_with_query(
                0,
                params.x.clone(),
                self.h_commitment.clone(),
                scalar!(self.expected_h_eval.clone()),
            ),
            EvaluationQuery::new(
                0,
                params.x.clone(),
                format!("{}_random_commitment", self.key),
                params.random_commitment.clone(),
                params.random_eval.clone(),
            ),
        ]
    }
}
