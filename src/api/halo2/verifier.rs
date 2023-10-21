use super::format_advice_commitment_key;
use super::format_fixed_commitment_key;
use super::format_instance_commitment_key;
use super::protocols::lookup;
use super::protocols::permutation;
use super::protocols::vanish;
use super::query::CommitQuery;
use super::query::EvaluationQuery;
use super::query::EvaluationQuerySchemaRc;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::commit;
use crate::echeckpoint;
use crate::scalar;
use crate::scheckpoint;
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Expression;
use std::collections::BTreeMap;
use std::iter;
use std::rc::Rc;

pub struct VerifierParams<C: CurveAffine> {
    pub key: String,
    pub gates: Vec<Expression<C::ScalarExt>>,
    pub n: u32,
    pub l: u32,

    pub(crate) lookup_evaluated: Vec<lookup::Evaluated<C>>,
    pub permutation_evaluated: permutation::Evaluated<C>,

    pub instance_commitments: Vec<AstPointRc<C>>,
    pub instance_evals: Vec<AstScalarRc<C>>,
    pub instance_queries: Vec<(usize, i32)>,

    pub advice_commitments: Vec<AstPointRc<C>>,
    pub advice_evals: Vec<AstScalarRc<C>>,
    pub advice_queries: Vec<(usize, i32)>,

    pub fixed_commitments: Vec<AstPointRc<C>>,
    pub fixed_evals: Vec<AstScalarRc<C>>,
    pub fixed_queries: Vec<(usize, i32)>,

    pub permutation_commitments: Vec<AstPointRc<C>>,
    pub permutation_evals: Vec<AstScalarRc<C>>,

    pub vanish_commitments: Vec<AstPointRc<C>>,
    pub random_commitment: AstPointRc<C>,

    pub w: Vec<AstPointRc<C>>,

    pub random_eval: AstScalarRc<C>,
    pub beta: AstScalarRc<C>,
    pub gamma: AstScalarRc<C>,
    pub theta: AstScalarRc<C>,
    pub delta: AstScalarRc<C>,

    pub x: AstScalarRc<C>,
    pub x_next: AstScalarRc<C>,
    pub x_last: AstScalarRc<C>,
    pub x_inv: AstScalarRc<C>,
    pub xn: AstScalarRc<C>,

    pub y: AstScalarRc<C>,
    pub u: AstScalarRc<C>,
    pub v: AstScalarRc<C>,

    pub omega: C::ScalarExt,

    pub ls: Vec<AstScalarRc<C>>,
    pub l_blind: AstScalarRc<C>,
}
pub struct EvaluationProof<C: CurveAffine> {
    pub point: AstScalarRc<C>,
    pub s: EvaluationQuerySchemaRc<C>,
    pub w: AstPointRc<C>,
}

pub struct MultiOpenProof<C: CurveAffine> {
    pub w_x: EvaluationQuerySchemaRc<C>,
    pub w_g: EvaluationQuerySchemaRc<C>,
}

impl<C: CurveAffine> VerifierParams<C> {
    pub(crate) fn evaluate_expression(&self, expr: &Expression<C::ScalarExt>) -> AstScalarRc<C> {
        match expr {
            Expression::Constant(c) => sconst!(*c),
            Expression::Selector(_) => unreachable!(),
            Expression::Fixed { query_index, .. } => self.fixed_evals[*query_index].clone(),
            Expression::Advice { query_index, .. } => self.advice_evals[*query_index].clone(),
            Expression::Instance { query_index, .. } => self.instance_evals[*query_index].clone(),
            Expression::Negated(a) => sconst!(C::ScalarExt::zero()) - self.evaluate_expression(a),
            Expression::Sum(a, b) => self.evaluate_expression(a) + self.evaluate_expression(b),
            Expression::Product(a, b) => self.evaluate_expression(a) * self.evaluate_expression(b),
            Expression::Scaled(a, b) => sconst!(*b) * self.evaluate_expression(a),
        }
    }

    fn get_all_expression_evals(&self) -> Vec<AstScalarRc<C>> {
        iter::empty()
            .chain(self.gates.iter().map(|expr| self.evaluate_expression(expr)))
            .chain(self.permutation_evaluated.expressions(self).into_iter())
            .chain(
                self.lookup_evaluated
                    .iter()
                    .flat_map(|e| e.expressions(self)),
            )
            .collect()
    }

    fn x_rotate(&self, at: i32) -> AstScalarRc<C> {
        let omega_at = if at < 0 {
            self.omega.pow_vartime([(-at) as u64]).invert().unwrap()
        } else {
            self.omega.pow_vartime([(at) as u64])
        };
        sconst!(omega_at) * &self.x
    }

    fn get_all_queries(&self) -> Vec<EvaluationQuery<C>> {
        let expression_evals = self
            .get_all_expression_evals()
            .into_iter()
            .enumerate()
            .map(|(i, e)| scheckpoint!(format!("expression {}", i), e))
            .collect();

        let mut queries = vec![];
        {
            let instance_commitments = &self.instance_commitments;
            let instance_evals = &self.instance_evals;
            let advice_commitments = &self.advice_commitments;
            let advice_evals = &self.advice_evals;
            let permutation = &self.permutation_evaluated;
            let lookups = &self.lookup_evaluated;

            for (query_index, &(column, at)) in self.instance_queries.iter().enumerate() {
                queries.push(EvaluationQuery::new(
                    at,
                    self.x_rotate(at),
                    format_instance_commitment_key(&self.key, column),
                    instance_commitments[column].clone(),
                    instance_evals[query_index].clone(),
                ))
            }

            for (query_index, &(column, at)) in self.advice_queries.iter().enumerate() {
                queries.push(EvaluationQuery::new(
                    at,
                    self.x_rotate(at),
                    format_advice_commitment_key(&self.key, column),
                    advice_commitments[column].clone(),
                    advice_evals[query_index].clone(),
                ))
            }

            queries.append(&mut permutation.queries(self));
            queries.append(&mut lookups.iter().flat_map(|p| p.queries(self)).collect());
        }

        for (query_index, &(column, at)) in self.fixed_queries.iter().enumerate() {
            queries.push(EvaluationQuery::new(
                at,
                self.x_rotate(at),
                format_fixed_commitment_key(&self.key, column),
                self.fixed_commitments[column].clone(),
                self.fixed_evals[query_index].clone(),
            ))
        }

        queries.append(
            &mut self
                .permutation_commitments
                .iter()
                .zip(self.permutation_evals.iter())
                .enumerate()
                .map(|(i, (commitment, eval))| {
                    EvaluationQuery::new(
                        0,
                        self.x.clone(),
                        format!("{}_permutation_commitments_{}", self.key, i),
                        commitment.clone(),
                        eval.clone(),
                    )
                })
                .collect(),
        );

        let vanish = vanish::Evaluated::build_from_verifier_params(&self, expression_evals);
        queries.append(&mut vanish.queries(self));

        queries
    }

    fn get_point_schemas(&self) -> Vec<EvaluationProof<C>> {
        let queries = self.get_all_queries();

        let mut queries_groups: BTreeMap<i32, (_, Vec<_>)> = BTreeMap::new();

        for query in queries {
            if let Some(queries) = queries_groups.get_mut(&query.rotation) {
                queries.1.push(query.s);
            } else {
                queries_groups.insert(query.rotation, (query.point, vec![query.s]));
            }
        }

        assert_eq!(self.w.len(), queries_groups.len());

        queries_groups
            .into_values()
            .enumerate()
            .map(|(i, (point, queries))| EvaluationProof {
                s: queries.into_iter().enumerate().fold(
                    scalar!(sconst!(C::ScalarExt::zero())),
                    |acc, (j, q)| {
                        echeckpoint!(
                            format!("eval acc {} {}", i, j),
                            (acc * scalar!(self.v.clone())
                                + echeckpoint!(format!("eval {} {}", i, j), q.0))
                            .0
                        )
                    },
                ),
                point,
                w: self.w[i].clone(),
            })
            .collect()
    }

    pub fn batch_multi_open_proofs(&self) -> MultiOpenProof<C> {
        let proofs = self.get_point_schemas();

        let mut w_x = None;
        let mut w_g = None;

        for (i, p) in proofs.into_iter().enumerate() {
            let s = &p.s;
            let w = Rc::new(CommitQuery {
                key: format!("{}_w{}", self.key, i),
                commitment: Some(p.w.clone()),
                eval: None,
            });

            w_x = w_x.map_or(Some(commit!(w.clone())), |w_x| {
                Some(scalar!(self.u.clone()) * w_x + commit!(w.clone()))
            });

            w_g = w_g.map_or(
                Some(scalar!(p.point.clone()) * commit!(w.clone()) + s.clone()),
                |w_g| {
                    Some(
                        scalar!(self.u.clone()) * w_g
                            + scalar!(p.point.clone()) * commit!(w)
                            + s.clone(),
                    )
                },
            );
        }

        MultiOpenProof {
            w_x: w_x.unwrap(),
            w_g: w_g.unwrap(),
        }
    }
}
