use super::super::query::EvaluationQuery;
use crate::api::arith::AstPoint;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::api::halo2::verifier::VerifierParams;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::VerifyingKey;
use std::rc::Rc;

#[derive(Debug)]
pub struct PermutedCommitments<C: CurveAffine> {
    pub(crate) permuted_input_commitment: AstPointRc<C>,
    pub(crate) permuted_table_commitment: AstPointRc<C>,
}

#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) input_expressions: Vec<Expression<C::ScalarExt>>,
    pub(crate) table_expressions: Vec<Expression<C::ScalarExt>>,
    pub(crate) product_eval: AstScalarRc<C>,
    pub(crate) product_next_eval: AstScalarRc<C>,
    pub(crate) permuted_input_eval: AstScalarRc<C>,
    pub(crate) permuted_input_inv_eval: AstScalarRc<C>,
    pub(crate) permuted_table_eval: AstScalarRc<C>,

    pub(crate) permuted_commitment: PermutedCommitments<C>,
    pub(crate) product_commitment: AstPointRc<C>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub(crate) fn build_from_transcript(
        index: usize,
        permuted_commitment: PermutedCommitments<C>,
        product_commitment: AstPointRc<C>,
        key: &str,
        vk: &VerifyingKey<C>,
        transcript: &mut Rc<AstTranscript<C>>,
    ) -> Self {
        let product_eval = transcript.read_scalar();
        let product_next_eval = transcript.read_scalar();
        let permuted_input_eval = transcript.read_scalar();
        let permuted_input_inv_eval = transcript.read_scalar();
        let permuted_table_eval = transcript.read_scalar();
        Evaluated {
            input_expressions: vk.cs.lookups[index].input_expressions.clone(),
            table_expressions: vk.cs.lookups[index].table_expressions.clone(),
            permuted_commitment,
            product_commitment,
            product_eval,
            product_next_eval,
            permuted_input_eval,
            permuted_input_inv_eval,
            permuted_table_eval,
            key: format!("{}_lookup_{}", key.clone(), index),
        }
    }

    pub fn expressions(&self, params: &VerifierParams<C>) -> Vec<AstScalarRc<C>> {
        todo!()
    }

    pub fn queries(
        &self,
        x: AstScalarRc<C>,
        x_inv: AstScalarRc<C>,
        x_next: AstScalarRc<C>,
    ) -> Vec<EvaluationQuery<C>> {
        vec![
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_product_commitment", self.key),
                self.product_commitment.clone(),
                self.product_eval.clone(),
            ),
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_permuted_input_commitment", self.key),
                self.permuted_commitment.permuted_input_commitment.clone(),
                self.permuted_input_eval.clone(),
            ),
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_permuted_table_commitment", self.key),
                self.permuted_commitment.permuted_table_commitment.clone(),
                self.permuted_table_eval.clone(),
            ),
            EvaluationQuery::new(
                -1,
                x_inv.clone(),
                format!("{}_permuted_input_commitment", self.key),
                self.permuted_commitment.permuted_input_commitment.clone(),
                self.permuted_input_inv_eval.clone(),
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
