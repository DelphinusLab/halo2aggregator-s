use super::format_advice_commitment_key;
use super::format_fixed_commitment_key;
use super::format_instance_commitment_key;
use super::protocols::logup as lookup;
use super::protocols::permutation;
use super::protocols::shuffle;
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
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Expression;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::iter;
use std::rc::Rc;

pub struct VerifierParams<C: CurveAffine> {
    pub key: String,
    pub gates: Vec<Expression<C::ScalarExt>>,
    pub n: u32,
    pub l: u32,

    pub(crate) lookup_evaluated: Vec<lookup::Evaluated<C>>,
    pub(crate) shuffle_evaluated: Vec<shuffle::Evaluated<C>>,
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
    pub multiopen_challenges: Vec<AstScalarRc<C>>,
    pub multiopen_commitments: Vec<AstPointRc<C>>,

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
            .chain(
                self.shuffle_evaluated
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
            .map(|(_, e)| e)
            .collect();

        let mut queries = vec![];
        {
            let instance_commitments = &self.instance_commitments;
            let instance_evals = &self.instance_evals;
            let advice_commitments = &self.advice_commitments;
            let advice_evals = &self.advice_evals;
            let permutation = &self.permutation_evaluated;
            let lookups = &self.lookup_evaluated;
            let shuffles = &self.shuffle_evaluated;

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
            queries.append(&mut shuffles.iter().flat_map(|p| p.queries(self)).collect());
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

    fn get_point_schemas_gwc(&self) -> Vec<EvaluationProof<C>> {
        let queries = self.get_all_queries();

        let mut queries_groups: BTreeMap<i32, (_, Vec<_>)> = BTreeMap::new();

        for query in queries {
            if let Some(queries) = queries_groups.get_mut(&query.rotation) {
                queries.1.push(query.commitment + query.eval.unwrap());
            } else {
                queries_groups.insert(
                    query.rotation,
                    (query.point, vec![query.commitment + query.eval.unwrap()]),
                );
            }
        }

        let w = self.multiopen_commitments.clone();
        let v = self.multiopen_challenges[0].clone();

        assert_eq!(w.len(), queries_groups.len());

        queries_groups
            .into_values()
            .enumerate()
            .map(|(i, (point, queries))| EvaluationProof {
                s: queries.into_iter().enumerate().fold(
                    scalar!(sconst!(C::ScalarExt::zero())),
                    |acc, (j, q)| {
                        echeckpoint!(
                            format!("eval acc {} {}", i, j),
                            (acc * scalar!(v.clone())
                                + echeckpoint!(format!("eval {} {}", i, j), q.0))
                            .0
                        )
                    },
                ),
                point,
                w: w[i].clone(),
            })
            .collect()
    }

    pub fn batch_multi_open_proofs_gwc(&self) -> MultiOpenProof<C> {
        let proofs = self.get_point_schemas_gwc();

        let mut w_x = None;
        let mut w_g = None;

        let u = self.multiopen_challenges[1].clone();

        for (i, p) in proofs.into_iter().enumerate() {
            let s = &p.s;
            let w = Rc::new(CommitQuery {
                key: format!("{}_w{}", self.key, i),
                commitment: Some(p.w.clone()),
                eval: None,
            });

            w_x = w_x.map_or(Some(commit!(w.clone())), |w_x| {
                Some(scalar!(u.clone()) * w_x + commit!(w.clone()))
            });

            w_g = w_g.map_or(
                Some(scalar!(p.point.clone()) * commit!(w.clone()) + s.clone()),
                |w_g| {
                    Some(
                        scalar!(u.clone()) * w_g
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

    fn get_point_schemas_shplonk(
        &self,
    ) -> (
        Vec<(
            BTreeSet<i32>,
            Vec<(EvaluationQuerySchemaRc<C>, BTreeMap<i32, AstScalarRc<C>>)>,
        )>,
        Vec<(i32, AstScalarRc<C>)>,
    ) {
        let queries = self.get_all_queries();

        // Order points according to their rotation
        let mut rotation_point_map = BTreeMap::new();
        for query in queries.clone() {
            rotation_point_map
                .entry(query.rotation)
                .or_insert_with(|| query.point);
        }

        // All points appear in queries
        let super_point_set: Vec<_> = rotation_point_map.into_iter().collect();

        let mut commitment_rotation_set_map: Vec<(
            _,
            BTreeSet<i32>,
            BTreeMap<i32, AstScalarRc<C>>,
        )> = vec![];
        for query in queries.clone() {
            let rotation = query.rotation;
            if let Some(pos) = commitment_rotation_set_map
                .iter()
                .position(|(commitment, _, _)| *commitment == query.commitment)
            {
                let (_, rotation_set, eval_map) = &mut commitment_rotation_set_map[pos];
                rotation_set.insert(rotation);
                eval_map.insert(rotation, query.eval.unwrap().0.get_eval());
            } else {
                let rotation_set = BTreeSet::from([rotation]);
                let eval_map = BTreeMap::from([(rotation, query.eval.unwrap().0.get_eval())]);
                commitment_rotation_set_map.push((query.commitment, rotation_set, eval_map));
            };
        }

        let mut rotation_set_commitment_map = BTreeMap::<BTreeSet<_>, Vec<_>>::new();
        for (commitment, rotation_set, eval_map) in commitment_rotation_set_map {
            let commitments = rotation_set_commitment_map
                .entry(rotation_set.clone())
                .or_insert_with(Vec::new);
            commitments.push((commitment.clone(), eval_map));
        }

        let rotation_sets = rotation_set_commitment_map.into_iter().collect::<Vec<_>>();

        (rotation_sets, super_point_set)
    }

    fn evaluate_vanishing_polynomial(
        roots: Vec<AstScalarRc<C>>,
        x: AstScalarRc<C>,
    ) -> AstScalarRc<C> {
        if roots.len() == 0 {
            sconst!(C::ScalarExt::one())
        } else {
            roots
                .into_iter()
                .map(|root| x.clone() - root)
                .reduce(|l, r| l * r)
                .unwrap()
        }
    }

    fn eval_polynomial(cosets: Vec<AstScalarRc<C>>, x: AstScalarRc<C>) -> AstScalarRc<C> {
        if cosets.len() == 0 {
            sconst!(C::ScalarExt::zero())
        } else {
            cosets
                .into_iter()
                .rev()
                .reduce(|l, r| (l * x.clone()) + r)
                .unwrap()
        }
    }

    fn lagrange_interpolate(
        points: Vec<AstScalarRc<C>>,
        evals: Vec<AstScalarRc<C>>,
    ) -> Vec<AstScalarRc<C>> {
        assert_eq!(points.len(), evals.len());
        if points.len() == 1 {
            // Constant polynomial
            vec![evals[0].clone()]
        } else {
            let mut denoms = Vec::with_capacity(points.len());
            for (j, x_j) in points.iter().enumerate() {
                let mut denom = Vec::with_capacity(points.len() - 1);
                for x_k in points
                    .iter()
                    .enumerate()
                    .filter(|&(k, _)| k != j)
                    .map(|a| a.1)
                {
                    denom.push(sconst!(C::ScalarExt::one()) / (x_j.clone() - x_k));
                }
                denoms.push(denom);
            }

            let mut final_poly = vec![sconst!(C::ScalarExt::zero()); points.len()];
            for (j, (denoms, eval)) in denoms.into_iter().zip(evals.iter()).enumerate() {
                let mut tmp: Vec<_> = Vec::with_capacity(points.len());
                let mut product = Vec::with_capacity(points.len() - 1);
                tmp.push(sconst!(C::ScalarExt::one()));
                for (x_k, denom) in points
                    .iter()
                    .enumerate()
                    .filter(|&(k, _)| k != j)
                    .map(|a| a.1)
                    .zip(denoms.into_iter())
                {
                    product.resize(tmp.len() + 1, sconst!(C::ScalarExt::zero()));
                    for ((a, b), product) in tmp
                        .clone()
                        .into_iter()
                        .chain(std::iter::once(sconst!(C::ScalarExt::zero())))
                        .zip(
                            std::iter::once(sconst!(C::ScalarExt::zero()))
                                .chain(tmp.clone().into_iter()),
                        )
                        .zip(product.iter_mut())
                    {
                        *product = b * denom.clone() - a * (denom.clone() * x_k);
                    }
                    std::mem::swap(&mut tmp, &mut product);
                }
                assert_eq!(tmp.len(), points.len());
                assert_eq!(product.len(), points.len() - 1);
                for (final_coeff, interpolation_coeff) in final_poly.iter_mut().zip(tmp.into_iter())
                {
                    *final_coeff = final_coeff.clone() + interpolation_coeff * eval;
                }
            }
            final_poly
        }
    }

    pub fn batch_multi_open_proofs_shplonk(&self) -> MultiOpenProof<C> {
        let (rotation_sets, super_point_set) = self.get_point_schemas_shplonk();

        let y = self.multiopen_challenges[0].clone();
        let v = self.multiopen_challenges[1].clone();
        let u = self.multiopen_challenges[2].clone();

        let h1 = self.multiopen_commitments[0].clone();
        let h2 = self.multiopen_commitments[1].clone();

        let mut z_0 = None;
        let mut z_0_diff_inverse = None;

        let mut r_outer_acc = sconst!(C::ScalarExt::zero());
        let mut outer_msm = None;
        for (i, rotation_set) in rotation_sets.iter().enumerate() {
            let diffs: Vec<_> = super_point_set
                .iter()
                .filter_map(|point| {
                    if !rotation_set.0.contains(&point.0) {
                        Some(point.1.clone())
                    } else {
                        None
                    }
                })
                .collect();
            let mut z_diff_i = Self::evaluate_vanishing_polynomial(diffs, u.clone());
            if i == 0 {
                let points = super_point_set
                    .iter()
                    .filter_map(|point| {
                        if rotation_set.0.contains(&point.0) {
                            Some(point.1.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                z_0 = Some(Self::evaluate_vanishing_polynomial(points, u.clone()));
                z_0_diff_inverse = Some(sconst!(C::ScalarExt::one()) / z_diff_i);
                z_diff_i = sconst!(C::ScalarExt::one());
            } else {
                z_diff_i = z_diff_i * z_0_diff_inverse.clone().unwrap();
            }

            let mut r_inner_acc = sconst!(C::ScalarExt::zero());
            let mut inner_msm = None;
            for (_j, (commitment_data, evals)) in rotation_set.1.clone().into_iter().enumerate() {
                let points: Vec<_> = super_point_set
                    .iter()
                    .filter_map(|point| {
                        if rotation_set.0.contains(&point.0) {
                            Some(point.1.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                let evals: Vec<_> = super_point_set
                    .iter()
                    .filter_map(|point| evals.get(&point.0).map(|x| x.clone()))
                    .collect();
                let r_x = Self::lagrange_interpolate(points, evals);
                let r_eval = Self::eval_polynomial(r_x, u.clone());
                r_inner_acc = y.clone() * r_inner_acc + r_eval;
                inner_msm = if inner_msm.is_some() {
                    Some(scalar!(y.clone()) * inner_msm.unwrap() + commitment_data)
                } else {
                    Some(commitment_data)
                };
            }
            r_outer_acc = v.clone() * r_outer_acc + r_inner_acc * z_diff_i.clone();

            let inner_msm = inner_msm.unwrap() * scalar!(z_diff_i.clone());
            outer_msm = if outer_msm.is_some() {
                Some(scalar!(v.clone()) * outer_msm.unwrap() + inner_msm)
            } else {
                Some(inner_msm)
            };
        }

        let h1 = commit!(Rc::new(CommitQuery {
            key: format!("{}_h1", self.key),
            commitment: Some(h1),
            eval: None,
        }));

        let h2 = commit!(Rc::new(CommitQuery {
            key: format!("{}_h2", self.key),
            commitment: Some(h2),
            eval: None,
        }));

        let mut outer_msm = outer_msm.unwrap();
        outer_msm = outer_msm + scalar!(r_outer_acc);
        outer_msm = outer_msm + scalar!(sconst!(C::ScalarExt::zero()) - z_0.unwrap()) * h1;
        outer_msm = outer_msm + scalar!(u) * h2.clone();

        MultiOpenProof {
            w_x: h2,
            w_g: outer_msm,
        }
    }
}
