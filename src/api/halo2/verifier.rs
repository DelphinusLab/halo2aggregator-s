use super::protocols::lookup;
use super::protocols::permutation;
use super::query::CommitQuery;
use super::query::EvaluationQuery;
use super::query::EvaluationQuerySchemaRc;
use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use crate::commit;
use crate::scalar;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Expression;
use std::collections::BTreeMap;
use std::rc::Rc;

pub struct VerifierParams<C: CurveAffine> {
    pub key: String,
    pub gates: Vec<Expression<C::ScalarExt>>,
    pub n: u32,
    pub l: u32,

    pub(crate) lookup_evaluated: Vec<lookup::Evaluated<C>>,
    pub permutation_evaluated: permutation::Evaluated<C>,

    pub instance_commitments: Vec<Rc<AstPoint<C>>>,
    pub instance_evals: Vec<Rc<AstScalar<C>>>,
    pub instance_queries: Vec<(usize, i32)>,

    pub advice_commitments: Vec<Rc<AstPoint<C>>>,
    pub advice_evals: Vec<Rc<AstScalar<C>>>,
    pub advice_queries: Vec<(usize, i32)>,

    pub fixed_commitments: Vec<Rc<AstPoint<C>>>,
    pub fixed_evals: Vec<Rc<AstScalar<C>>>,
    pub fixed_queries: Vec<(usize, i32)>,

    pub permutation_commitments: Vec<Rc<AstPoint<C>>>,
    pub permutation_evals: Vec<Rc<AstScalar<C>>>,

    pub vanish_commitments: Vec<Rc<AstPoint<C>>>,
    pub random_commitment: Rc<AstPoint<C>>,

    pub w: Vec<Rc<AstPoint<C>>>,

    pub random_eval: Rc<AstScalar<C>>,
    pub beta: Rc<AstScalar<C>>,
    pub gamma: Rc<AstScalar<C>>,
    pub theta: Rc<AstScalar<C>>,
    pub delta: Rc<AstScalar<C>>,

    pub x: Rc<AstScalar<C>>,
    pub x_next: Rc<AstScalar<C>>,
    pub x_last: Rc<AstScalar<C>>,
    pub x_inv: Rc<AstScalar<C>>,
    pub xn: Rc<AstScalar<C>>,

    pub y: Rc<AstScalar<C>>,
    pub u: Rc<AstScalar<C>>,
    pub v: Rc<AstScalar<C>>,
    pub omega: Rc<AstScalar<C>>,
}
pub struct EvaluationProof<C: CurveAffine> {
    pub point: Rc<AstScalar<C>>,
    pub s: EvaluationQuerySchemaRc<C>,
    pub w: Rc<AstPoint<C>>,
}

pub struct MultiOpenProof<C: CurveAffine> {
    pub w_x: EvaluationQuerySchemaRc<C>,
    pub w_g: EvaluationQuerySchemaRc<C>,
}

impl<C: CurveAffine> VerifierParams<C> {
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
