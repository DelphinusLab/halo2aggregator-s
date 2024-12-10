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
pub(crate) struct ZEvalSet<C: CurveAffine> {
    pub(crate) commitment: AstPointRc<C>,
    pub(crate) eval: AstScalarRc<C>,
    pub(crate) next_eval: AstScalarRc<C>,
    pub(crate) last_eval: Option<AstScalarRc<C>>,
}

#[derive(Debug)]
pub(crate) struct Evaluated<C: CurveAffine> {
    pub(crate) key: String,
    pub(crate) blinding_factors: usize,
    pub(crate) input_expressions_sets: Vec<InputExpressionSet<C>>,
    pub(crate) table_expressions: Vec<Expression<C::ScalarExt>>,
    pub(crate) multiplicity_eval: AstScalarRc<C>,
    pub(crate) multiplicity_commitment: MultiplicityCommitment<C>,
    pub(crate) z_eval_set: Vec<ZEvalSet<C>>,
}

impl<C: CurveAffine> Evaluated<C> {
    pub(crate) fn build_from_transcript(
        index: usize,
        multiplicity_commitment: MultiplicityCommitment<C>,
        z_commitment_set: Vec<AstPointRc<C>>,
        key: &str,
        vk: &VerifyingKey<C>,
        transcript: &mut Rc<AstTranscript<C>>,
    ) -> Self {
        let multiplicity_eval = transcript.read_scalar();
        let mut iter = z_commitment_set.into_iter();
        let mut z_eval_set = vec![];
        while let Some(commitment) = iter.next() {
            let eval = transcript.read_scalar();
            let next_eval = transcript.read_scalar();
            let last_eval = if iter.len() > 0 {
                Some(transcript.read_scalar())
            } else {
                None
            };
            z_eval_set.push(ZEvalSet {
                commitment,
                eval,
                next_eval,
                last_eval,
            })
        }

        Evaluated {
            input_expressions_sets: vk.cs.lookups[index]
                .input_expressions_sets
                .iter()
                .map(|set| InputExpressionSet(set.0.clone()))
                .collect(),
            table_expressions: vk.cs.lookups[index].table_expressions.clone(),
            multiplicity_commitment,
            multiplicity_eval,
            z_eval_set,
            blinding_factors: vk.cs.blinding_factors(),
            key: format!("{}_lookup_{}", key, index),
        }
    }

    pub fn expressions(&self, params: &VerifierParams<C>) -> Vec<AstScalarRc<C>> {
        let one = &sconst!(C::ScalarExt::one());

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

        let phis = self
            .input_expressions_sets
            .iter()
            .map(|set| {
                set.0
                    .iter()
                    .map(|expressions| {
                        expressions
                            .iter()
                            .map(|expression| params.evaluate_expression(expression))
                            .reduce(|acc, x| acc * theta + x)
                            .unwrap()
                            + beta
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let tau = self
            .table_expressions
            .iter()
            .map(|expression| params.evaluate_expression(expression))
            .reduce(|acc, x| acc * theta + x)
            .unwrap()
            + beta;

        let product_fis = phis
            .iter()
            .map(|phi| phi.iter().skip(1).fold(phi[0].clone(), |acc, e| acc * e))
            .collect::<Vec<_>>();

        let sum_product_fis = phis
            .iter()
            .map(|phi| {
                if phi.len() > 1 {
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
                }
            })
            .collect::<Vec<_>>();

        let first_set = self.z_eval_set.first().unwrap();
        let last_set = self.z_eval_set.last().unwrap();
        let z0_wx = &first_set.next_eval;
        let z0_x = &first_set.eval;
        let zl_x = &last_set.eval;

        let left = (tau.clone() * (z0_wx - z0_x) + m_x) * &product_fis[0];
        let right = tau * &sum_product_fis[0];

        let mut res = vec![
            l_0 * z0_x,
            (l_last * zl_x),
            ((left - right) * (one - (l_last + l_blind))),
        ];

        // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
        self.z_eval_set
            .iter()
            .skip(1)
            .zip(self.z_eval_set.iter())
            .for_each(|(set, pre_set)| {
                res.push(l_0 * (&set.eval - &pre_set.last_eval.clone().unwrap()))
            });

        /*
            φ_i(X) = f_i(X) + α
            LHS = Π(φ_i(X)) * (ϕ(gX) - ϕ(X))
            RHS = Π(φ_i(X)) * (∑ 1/(φ_i(X)))
        */
        for ((set, product_fi), sum_product_fi) in self
            .z_eval_set
            .iter()
            .zip(product_fis.iter())
            .zip(sum_product_fis.iter())
            .skip(1)
        {
            res.push(
                ((&set.next_eval - &set.eval) * product_fi - sum_product_fi)
                    * (one - (l_last + l_blind)),
            )
        }

        res
    }

    pub fn queries(&self, params: &VerifierParams<C>) -> Vec<EvaluationQuery<C>> {
        let x = &params.x;
        let x_next = &params.x_next;
        let x_last = &params.x_last;

        std::iter::empty()
            .chain(Some(EvaluationQuery::new(
                0,
                x.clone(),
                format!("{}_multiplicity_commitment", self.key),
                self.multiplicity_commitment.0.clone(),
                self.multiplicity_eval.clone(),
            )))
            .chain(self.z_eval_set.iter().enumerate().flat_map(|(i, set)| {
                std::iter::empty()
                    .chain(Some(EvaluationQuery::new(
                        0,
                        x.clone(),
                        format!("{}_z_commitment_{}", self.key, i),
                        set.commitment.clone(),
                        set.eval.clone(),
                    )))
                    .chain(Some(EvaluationQuery::new(
                        1,
                        x_next.clone(),
                        format!("{}_z_commitment_{}", self.key, i),
                        set.commitment.clone(),
                        set.next_eval.clone(),
                    )))
            }))
            .chain(
                self.z_eval_set
                    .iter()
                    .enumerate()
                    .rev()
                    .skip(1)
                    .map(|(i, set)| {
                        EvaluationQuery::new(
                            -((self.blinding_factors + 1) as i32),
                            x_last.clone(),
                            format!("{}_z_commitment_{}", self.key, i),
                            set.commitment.clone(),
                            set.last_eval.clone().unwrap(),
                        )
                    }),
            )
            .collect()
    }
}
