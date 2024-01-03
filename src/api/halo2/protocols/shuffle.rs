use super::super::query::EvaluationQuery;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::api::halo2::verifier::VerifierParams;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::VerifyingKey;
use std::rc::Rc;

#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) input_expressions: Vec<Expression<C::ScalarExt>>,
    pub(crate) table_expressions: Vec<Expression<C::ScalarExt>>,
    pub(crate) product_eval: AstScalarRc<C>,
    pub(crate) product_next_eval: AstScalarRc<C>,

    pub(crate) product_commitment: AstPointRc<C>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub(crate) fn build_from_transcript(
        index: usize,
        product_commitment: AstPointRc<C>,
        key: &str,
        vk: &VerifyingKey<C>,
        transcript: &mut Rc<AstTranscript<C>>,
    ) -> Self {
        let product_eval = transcript.read_scalar();
        let product_next_eval = transcript.read_scalar();

        Evaluated {
            input_expressions: vk.cs.shuffles[index].input_expressions.clone(),
            table_expressions: vk.cs.shuffles[index].shuffle_expressions.clone(),
            product_commitment,
            product_eval,
            product_next_eval,
            key: format!("{}_shuffle_{}", key.clone(), index),
        }
    }

    pub fn expressions(&self, params: &VerifierParams<C>) -> Vec<AstScalarRc<C>> {
        let one = &sconst!(C::ScalarExt::one());

        let z_wx = &self.product_next_eval;
        let z_x = &self.product_eval;

        let gamma = &params.gamma;
        let theta = &params.theta;
        let l_0 = params.ls.last().unwrap();
        let l_last = &params.ls[0];
        let l_blind = &params.l_blind;

        let input_eval = self
            .input_expressions
            .iter()
            .map(|expression| params.evaluate_expression(expression))
            .reduce(|acc, x| acc * theta + x)
            .unwrap();

        let table_eval = self
            .table_expressions
            .iter()
            .map(|expression| params.evaluate_expression(expression))
            .reduce(|acc, x| acc * theta + x)
            .unwrap();

        vec![
            l_0 * (one - z_x),
            (l_last * ((z_x * z_x) - z_x)),
            (((z_wx * (table_eval + gamma)) - (z_x * (input_eval + gamma)))
                * (one - (l_last + l_blind))),
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
                format!("{}_product_next_commitment", self.key),
                self.product_commitment.clone(),
                self.product_next_eval.clone(),
            ),
        ]
    }
}
