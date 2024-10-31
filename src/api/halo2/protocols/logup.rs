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
pub struct MultiplicityCommitment<C: CurveAffine>(pub(crate) AstPointRc<C>);

#[derive(Debug)]
pub struct InputExpressionSet<C: CurveAffine>(pub(crate) Vec<Vec<Expression<C::ScalarExt>>>);


#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) input_expressions_sets: Vec<InputExpressionSet<C>>,
    pub(crate) table_expressions: Vec<Expression<C::ScalarExt>>,
    pub(crate) grand_sum_eval: AstScalarRc<C>,
    pub(crate) grand_sum_next_eval: AstScalarRc<C>,
    pub(crate) multiplicity_eval: AstScalarRc<C>,

    pub(crate) multiplicity_commitment: MultiplicityCommitment<C>,
    pub(crate) grand_sum_commitment: AstPointRc<C>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub(crate) fn build_from_transcript(
        index: usize,
        multiplicity_commitment: MultiplicityCommitment<C>,
        grand_sum_commitment: AstPointRc<C>,
        key: &str,
        vk: &VerifyingKey<C>,
        transcript: &mut Rc<AstTranscript<C>>,
    ) -> Self {
        let grand_sum_eval = transcript.read_scalar();
        let grand_sum_next_eval = transcript.read_scalar();
        let multiplicity_eval = transcript.read_scalar();
        Evaluated {
            input_expressions_sets: vk.cs.lookups[index].input_expressions_sets.iter().map(|set|InputExpressionSet(set.0.clone())).collect(),
            table_expressions: vk.cs.lookups[index].table_expressions.clone(),
            grand_sum_commitment,
            multiplicity_commitment,
            grand_sum_eval,
            grand_sum_next_eval,
            multiplicity_eval,
            key: format!("{}_lookup_{}", key.clone(), index),
        }
    }

    pub fn expressions(&self, params: &VerifierParams<C>) -> Vec<AstScalarRc<C>> {
        let one = &sconst!(C::ScalarExt::one());

        let z_wx = &self.grand_sum_next_eval;
        let z_x = &self.grand_sum_eval;
        let m_x = &self.multiplicity_eval;

        let beta = &params.beta;
        let theta = &params.theta;
        let l_0 = params.ls.last().unwrap();
        let l_last = &params.ls[0];
        let l_blind = &params.l_blind;

        /*
             φ_i(X) = f_i(X) + α
             τ(X) = t(X) + α
             LHS = τ(X) * Π(φ_i(X)) * (ϕ(gX) - ϕ(X))
             RHS = τ(X) * Π(φ_i(X)) * (∑ 1/(φ_i(X)) - m(X) / τ(X))
             <=>
             LHS = (τ(X) * (ϕ(gX) - ϕ(X)) + m(x)) *Π(φ_i(X))
             RHS = τ(X) * Π(φ_i(X)) * (∑ 1/(φ_i(X)))
        */

        let phi = self
            .input_expressions_sets[0].0
            .iter()
            .map(|expressions| {
                expressions
                    .iter()
                    .map(|expression| params.evaluate_expression(expression))
                    .reduce(|acc, x| acc * theta + x)
                    .unwrap()
                    + beta
            })
            .collect::<Vec<_>>();

        let tau = self
            .table_expressions
            .iter()
            .map(|expression| params.evaluate_expression(expression))
            .reduce(|acc, x| acc * theta + x)
            .unwrap()
            + beta;

        let product_fi = phi.iter().skip(1).fold(phi[0].clone(), |acc, e| acc * e);

        let sum_product_fi = if phi.len() > 1 {
            (0..phi.len())
                .map(|i| {
                    phi.iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, fi)| fi.clone())
                        .reduce(|acc, e| acc * e)
                        .unwrap()
                })
                .reduce(|acc, x| acc + x)
                .unwrap()
        } else {
            one.clone()
        };

        let left = (tau.clone() * (z_wx - z_x) + m_x) * product_fi;
        let right = tau * sum_product_fi;

        vec![
            l_0 * z_x,
            (l_last * z_x),
            ((left - right) * (one - (l_last + l_blind))),
        ]
    }

    pub fn queries(&self, params: &VerifierParams<C>) -> Vec<EvaluationQuery<C>> {
        let x = &params.x;
        let x_next = &params.x_next;
        vec![
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_grand_sum_commitment", self.key),
                self.grand_sum_commitment.clone(),
                self.grand_sum_eval.clone(),
            ),
            EvaluationQuery::new(
                1,
                x_next.clone(),
                format!("{}_grand_sum_commitment", self.key),
                self.grand_sum_commitment.clone(),
                self.grand_sum_next_eval.clone(),
            ),
            EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_multiplicity_commitment", self.key),
                self.multiplicity_commitment.0.clone(),
                self.multiplicity_eval.clone(),
            ),
        ]
    }
}
