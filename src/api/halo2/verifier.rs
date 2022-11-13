use super::protocols::lookup;
use super::protocols::permutation;
use super::query::CommitQuery;
use super::query::EvaluationQuery;
use super::query::EvaluationQuerySchemaRc;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::commit;
use crate::scalar;
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
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
    pub omega: AstScalarRc<C>,

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
            Expression::Negated(a) => {
                sconst!(C::ScalarExt::from(0u64)) - self.evaluate_expression(a)
            }
            Expression::Sum(a, b) => self.evaluate_expression(a) + self.evaluate_expression(b),
            Expression::Product(a, b) => self.evaluate_expression(a) * self.evaluate_expression(b),
            Expression::Scaled(a, b) => sconst!(*b) * self.evaluate_expression(a),
        }
    }

    fn get_all_expressions_eval(&self) -> Vec<AstScalarRc<C>> {
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

    fn get_all_queries(&self) -> Vec<EvaluationQuery<C>> {
        todo!()
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
                s: queries
                    .into_iter()
                    .reduce(|acc, q| scalar!(self.v.clone()) * acc + q)
                    .unwrap(),
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
