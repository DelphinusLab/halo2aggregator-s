use super::super::query::EvaluationQuery;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::api::halo2::verifier::VerifierParams;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use crate::sconst;
use crate::spow;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Expression;
use std::rc::Rc;

#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) shuffle_group: Vec<(Vec<Expression<C::ScalarExt>>, Vec<Expression<C::ScalarExt>>)>,
    pub(crate) product_eval: AstScalarRc<C>,
    pub(crate) product_next_eval: AstScalarRc<C>,

    pub(crate) product_commitment: AstPointRc<C>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub(crate) fn build_from_transcript(
        index: usize,
        product_commitment: AstPointRc<C>,
        key: &str,
        shuffle_group: Vec<(Vec<Expression<C::ScalarExt>>, Vec<Expression<C::ScalarExt>>)>,
        transcript: &mut Rc<AstTranscript<C>>,
    ) -> Self {
        let product_eval = transcript.read_scalar();
        let product_next_eval = transcript.read_scalar();

        Evaluated {
            shuffle_group,
            product_commitment,
            product_eval,
            product_next_eval,
            key: format!("{}_shuffle_{}", key, index),
        }
    }

    pub fn expressions(&self, params: &VerifierParams<C>) -> Vec<AstScalarRc<C>> {
        let one = &sconst!(C::ScalarExt::one());

        let z_wx = &self.product_next_eval;
        let z_x = &self.product_eval;

        let beta = &params.beta;
        let theta = &params.theta;
        let l_0 = params.ls.last().unwrap();
        let l_last = &params.ls[0];
        let l_blind = &params.l_blind;
        let (input_eval, table_eval) = self
            .shuffle_group
            .iter()
            .enumerate()
            .map(|(i, expressions)| {
                let challenge = &spow!(beta.clone(), 1 + i as u32);
                let input_eval = expressions
                    .0
                    .iter()
                    .map(|expression| params.evaluate_expression(expression))
                    .reduce(|acc, x| acc * theta + x)
                    .unwrap();

                let table_eval = expressions
                    .1
                    .iter()
                    .map(|expression| params.evaluate_expression(expression))
                    .reduce(|acc, x| acc * theta + x)
                    .unwrap();
                (input_eval + challenge, table_eval + challenge)
            })
            .reduce(|acc, x| (acc.0 * x.0, acc.1 * x.1))
            .unwrap();

        vec![
            l_0 * (one - z_x),
            (l_last * ((z_x * z_x) - z_x)),
            (((z_wx * table_eval) - (z_x * input_eval)) * (one - (l_last + l_blind))),
        ]
    }

    pub fn queries(&self, params: &VerifierParams<C>) -> Vec<EvaluationQuery<C>> {
        let x = &params.x;
        let x_next = &params.x_next;
        vec![
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_product_commitment", self.key),
                self.product_commitment.clone(),
                self.product_eval.clone(),
            ),
            EvaluationQuery::new(
                1,
                x_next.clone(),
                format!("{}_product_commitment", self.key),
                self.product_commitment.clone(),
                self.product_next_eval.clone(),
            ),
        ]
    }
}
