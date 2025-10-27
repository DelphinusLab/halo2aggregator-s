use crate::api::arith::*;
use crate::api::halo2::query::CommitQuery;
use crate::api::halo2::query::EvaluationQuerySchemaRc;
use crate::api::halo2::verifier::MultiOpenProof;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use crate::commit;
use crate::eval;
use crate::pcheckpoint;
use crate::pconst;
use crate::scalar;
use crate::sconst;
use crate::spow;
use ark_std::iterable::Iterable;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Engine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MultiMillerLoop;
use itertools::chain;
use itertools::izip;
use plonkish_backend::backend::hyperplonk::verifier::pcs_query;
use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierParam;
use plonkish_backend::util::expression::rotate::Lexical;
use plonkish_backend::util::expression::CommonPolynomial;
use plonkish_backend::util::expression::Expression;
use plonkish_backend::util::expression::Query;
use plonkish_backend::util::expression::Rotatable;
use plonkish_backend::util::expression::Rotation;
use plonkish_backend::util::BitIndex;
use std::collections::BTreeMap;
use std::iter;
use std::rc::Rc;

pub fn eq_xy<C: CurveAffine>(y: &[AstScalarRc<C>]) -> Vec<AstScalarRc<C>> {
    if y.is_empty() {
        return vec![sconst!(C::ScalarExt::zero())];
    }

    let expand_serial =
        |next_evals: &mut [AstScalarRc<C>], evals: &[AstScalarRc<C>], y_i: &AstScalarRc<C>| {
            for (next_eval, eval) in next_evals.chunks_mut(2).zip(evals.iter()) {
                let r = eval.clone() * y_i;
                next_eval[0] = eval.clone() - r.clone();
                next_eval[1] = r;
            }
        };

    let mut evals = vec![sconst!(C::ScalarExt::one())];
    for y_i in y.iter().rev() {
        let mut next_evals = vec![sconst!(C::ScalarExt::zero()); 2 * evals.len()];
        //TODO: if >32, try take multi-threads calc
        assert!(evals.len() <= 32);
        expand_serial(&mut next_evals, &evals, y_i);
        evals = next_evals;
    }

    evals
}

pub fn steps<C: CurveAffine>(start: AstScalarRc<C>) -> impl Iterator<Item = AstScalarRc<C>> {
    steps_by(start, sconst!(C::ScalarExt::one()))
}

pub fn steps_by<C: CurveAffine>(
    start: AstScalarRc<C>,
    step: AstScalarRc<C>,
) -> impl Iterator<Item = AstScalarRc<C>> {
    iter::successors(Some(start), move |state| Some(step.clone() + state))
}

pub fn powers<C: CurveAffine>(scalar: AstScalarRc<C>) -> impl Iterator<Item = AstScalarRc<C>> {
    iter::successors(Some(sconst!(C::ScalarExt::one())), move |power| {
        Some(scalar.clone() * power)
    })
}

pub fn squares<C: CurveAffine>(scalar: AstScalarRc<C>) -> impl Iterator<Item = AstScalarRc<C>> {
    iter::successors(Some(scalar), move |scalar| Some(spow!(scalar.clone(), 2)))
}

fn eval_and_quotient_scalars<C: CurveAffine>(
    y: AstScalarRc<C>,
    x: AstScalarRc<C>,
    z: AstScalarRc<C>,
    u: &[AstScalarRc<C>],
) -> (AstScalarRc<C>, Vec<AstScalarRc<C>>) {
    let num_vars = u.len();

    let squares_of_x = squares(x).take(num_vars + 1).collect::<Vec<_>>();
    //it is relevant with multilinear evaluation and transfer
    let offsets_of_x = {
        let mut offsets_of_x = squares_of_x
            .iter()
            .rev()
            .skip(1)
            .scan(sconst!(C::Scalar::one()), |state, power_of_x| {
                *state = state.clone() * power_of_x;
                Some(state.clone())
            })
            .collect::<Vec<_>>();
        offsets_of_x.reverse();
        offsets_of_x
    };
    // vs ：calc another seiral $V=\left[V_0, \ldots, V_n\right]$ ， $V_k=\left(s_n-1\right) /\left(s_k-1\right)=\left(x^{2^n}-\right.$ 1）$/\left(x^{2^k}-1\right)$ 。
    //prove $V_k=\sum_{j=0}^{2^{n-k}-1}\left(x^{2^k}\right)^j=\Phi_{n-k}\left(x^{2^k}\right)$（refer to definition of  $\Phi$ in paper）。
    let vs = {
        let v_numer = squares_of_x[num_vars].clone() - sconst!(C::ScalarExt::one());
        let v_denoms = squares_of_x
            .iter()
            .map(|square_of_x| {
                sconst!(C::ScalarExt::one()) / (square_of_x.clone() - sconst!(C::ScalarExt::one()))
            })
            .collect::<Vec<_>>();

        v_denoms
            .iter()
            .map(|v_denom| v_numer.clone() * v_denom)
            .collect::<Vec<_>>()
    };
    //merge r(x) and s(x)'s q_k(x)'s multiplier
    let q_scalars = izip!(powers(y), offsets_of_x, squares_of_x, &vs, &vs[1..], u)
        .map(|(power_of_y, offset_of_x, square_of_x, v_i, v_j, u_i)| {
            //this negative could not be moved to -G1 as this calculation is to multiple commitment.
            sconst!(C::ScalarExt::zero())
                - (power_of_y * offset_of_x + z.clone() * (square_of_x * v_j - u_i.clone() * v_i))
        })
        .collect::<Vec<_>>();

    //the -vs[0]*z eval's negative has been moved to -params.G1
    (vs[0].clone() * z, q_scalars)
}

pub fn barycentric_weights<C: CurveAffine>(points: &[AstScalarRc<C>]) -> Vec<AstScalarRc<C>> {
    let weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter(|(i, _)| i != &j)
                .map(|(_, point_i)| sconst!(C::ScalarExt::one()) / (point_j - point_i))
                .reduce(|acc, value| acc * value)
                .unwrap_or(sconst!(C::ScalarExt::one()))
        })
        .collect::<Vec<_>>();
    weights
}

pub fn inner_product<'a, 'b, C: CurveAffine>(
    lhs: impl IntoIterator<Item = &'a AstScalarRc<C>>,
    rhs: impl IntoIterator<Item = &'b AstScalarRc<C>>,
) -> AstScalarRc<C> {
    lhs.into_iter()
        .zip(rhs.into_iter())
        .map(|(lhs, rhs)| lhs * rhs)
        .reduce(|acc, product| acc + product)
        .unwrap()
}

pub fn barycentric_interpolate<C: CurveAffine>(
    weights: &[AstScalarRc<C>],
    points: &[AstScalarRc<C>],
    evals: &[AstScalarRc<C>],
    x: &AstScalarRc<C>,
) -> AstScalarRc<C> {
    let (coeffs, sum_inv) = {
        let coeffs = points
            .iter()
            .map(|point| sconst!(C::ScalarExt::one()) / (x - point))
            .collect::<Vec<_>>();

        let coeffs = coeffs
            .iter()
            .zip(weights.iter())
            .map(|(c, w)| c * w)
            .collect::<Vec<_>>();

        let sum = coeffs
            .iter()
            .fold(sconst!(C::ScalarExt::zero()), |sum, coeff| sum + coeff);
        let sum_inv = sconst!(C::ScalarExt::one()) / sum;
        (coeffs, sum_inv)
    };
    inner_product(&coeffs, evals) * sum_inv
}

// replace f(0) by sum-f(1) => msg[sum-f(1),f(1),f(2),f(3)..]
fn verify_zero_sumcheck<C: CurveAffine>(
    msgs: &[Vec<AstScalarRc<C>>],
    challengs: &[AstScalarRc<C>],
    degree: usize,
) -> AstScalarRc<C> {
    let mut sum = sconst!(C::ScalarExt::zero());
    let points = steps::<C>(sconst!(C::ScalarExt::zero()))
        .take(degree + 1)
        .collect::<Vec<_>>();
    let weights = barycentric_weights(&points);

    for (msg, x) in msgs.iter().zip(challengs.iter()) {
        //f_i(r)=f_{i+1}(0)+f_{i+1}(1)
        sum = barycentric_interpolate(
            &weights,
            &points,
            &chain!(
                iter::once(sum - &msg[1]),
                msg[1..].iter().map(|x| x.clone())
            )
            .collect::<Vec<_>>(),
            x,
        );
    }
    sum
}

pub fn evaluate_expression<C: CurveAffine, R: Rotatable + From<usize>>(
    expression: &Expression<C::ScalarExt>,
    num_vars: usize,
    evals: &BTreeMap<Query, AstScalarRc<C>>,
    protocol_challenges: &[AstScalarRc<C>],
    ys: &[&[AstScalarRc<C>]],
    sumcheck_challengs: &[AstScalarRc<C>],
) -> AstScalarRc<C> {
    let rotatable = R::from(num_vars);

    let identity = identity_eval(sumcheck_challengs);
    let lagranges = {
        expression
            .used_langrange()
            .into_iter()
            .map(|i| (i, lagrange_eval(sumcheck_challengs, rotatable.nth(i))))
            .collect::<BTreeMap<_, _>>()
    };
    let eq_xys = ys
        .iter()
        .map(|y| eq_xy_eval(sumcheck_challengs, y))
        .collect::<Vec<_>>();
    expression.evaluate(
        &|scalar| sconst!(scalar),
        &|poly| match poly {
            CommonPolynomial::Identity => identity.clone(),
            CommonPolynomial::Lagrange(i) => lagranges[&i].clone(),
            CommonPolynomial::EqXY(idx) => eq_xys[idx].clone(),
        },
        &|query| evals[&query].clone(),
        &|idx| protocol_challenges[idx].clone(),
        &|scalar| sconst!(C::ScalarExt::zero()) - scalar,
        &|lhs, rhs| lhs.clone() + rhs,
        &|lhs, rhs| lhs.clone() * rhs,
        &|value, scalar| sconst!(scalar) * value,
    )
}

pub fn lagrange_eval<C: CurveAffine>(x: &[AstScalarRc<C>], b: usize) -> AstScalarRc<C> {
    assert!(!x.is_empty());

    x.iter()
        .enumerate()
        .map(|(idx, x_i)| {
            if b.nth_bit(idx) {
                x_i.clone()
            } else {
                sconst!(C::ScalarExt::one()) - x_i
            }
        })
        .reduce(|acc, e| acc * e)
        .unwrap()
}

pub fn eq_xy_eval<C: CurveAffine>(x: &[AstScalarRc<C>], y: &[AstScalarRc<C>]) -> AstScalarRc<C> {
    assert!(!x.is_empty());
    assert_eq!(x.len(), y.len());
    let one = sconst!(C::ScalarExt::one());
    x.iter()
        .zip(y)
        .map(|(x_i, y_i)| (one.clone() - x_i) * (one.clone() - y_i) + x_i * y_i)
        .reduce(|acc, e| acc * e)
        .unwrap()
}

fn identity_eval<C: CurveAffine>(x: &[AstScalarRc<C>]) -> AstScalarRc<C> {
    let two = sconst!(C::ScalarExt::from(2 as u64));
    inner_product(x, &powers(two).take(x.len()).collect::<Vec<_>>())
}

// verifier calc instance eval by self
fn instance_evals<C: CurveAffine>(
    num_vars: usize,
    expression: &Expression<C::ScalarExt>,
    instances: &[Vec<AstScalarRc<C>>],
    x: &[AstScalarRc<C>],
) -> Vec<(Query, AstScalarRc<C>)> {
    let mut instance_query = expression.used_query();
    instance_query.retain(|query| query.poly() < instances.len());

    let (min_rotation, max_rotation) = instance_query.iter().fold((0, 0), |(min, max), query| {
        (min.min(query.rotation().0), max.max(query.rotation().0))
    });
    let lagrange_evals = {
        let rotatable = Lexical::from(num_vars);
        let max_instance_len = instances.iter().map(Vec::len).max().unwrap_or_default();
        (-max_rotation..max_instance_len as i32 + min_rotation.abs())
            .map(|i| lagrange_eval(x, rotatable.nth(i)))
            .collect::<Vec<_>>()
    };

    instance_query
        .into_iter()
        .map(|query| {
            //here just poly*rotated x,
            //in general,it rotate poly,rotation>0, left rotate poly, rotation<0, right rotate poly
            //here just fix poly, rotate x points,if rotation>0,
            let offset = (max_rotation - query.rotation().0) as usize;
            let eval = inner_product(
                &instances[query.poly()],
                &lagrange_evals[offset..offset + instances[query.poly()].len()],
            );
            (query, eval)
        })
        .collect()
}

pub struct VerifierParamsBuilder<'a, E: MultiMillerLoop> {
    pub(crate) key: String,
    pub(crate) proof_index: usize,
    pub(crate) vk: &'a HyperPlonkVerifierParam<E::G1Affine>,
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>>
    VerifierParamsBuilder<'a, E>
{
    pub fn build(
        &self,
        instances: &Vec<Vec<E::Scalar>>,
    ) -> (
        MultiOpenProof<E::G1Affine>,
        Vec<AstPointRc<E::G1Affine>>,
        Vec<(usize, AstPointRc<E::G1Affine>)>,
        Rc<AstTranscript<C>>,
    ) {
        // Prepare ast for transcript.
        let mut transcript = Rc::new(AstTranscript::Init(self.proof_index));
        // for hyper plonk, just need instance evaluation and the commitment is not needed
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|e| sconst!(e.clone()))
                    .inspect(|v| transcript.common_scalar(v.clone()))
                    .collect()
            })
            .collect();
        //dummy commitment for instance
        //in Hyper, query indices are unified globally, need dummy commitments placed in instances part.
        let dummy_point = pconst!(<E as Engine>::G1Affine::default());
        let instance_dummy = (0..instances.len())
            .map(|_| dummy_point.clone())
            .collect::<Vec<_>>();

        let mut advice_cross_terms_commitments = vec![];
        for (_, idx) in self.vk.named_advices.iter() {
            let c = transcript.read_point();
            advice_cross_terms_commitments.push((*idx as usize, c))
        }

        let n_advice = self.vk.num_witness_polys;
        let advice_commitments = transcript
            .read_n_points(n_advice)
            .into_iter()
            .enumerate()
            .map(|(i, x)| pcheckpoint!(format!("advice commitment {} {}", self.proof_index, i), x))
            .collect::<Vec<_>>();

        let beta = transcript.squeeze_challenge();
        let lookup_m_commitments = transcript
            .read_n_points(self.vk.num_lookups)
            .into_iter()
            .enumerate()
            .map(|(i, x)| {
                pcheckpoint!(format!("lookup m commitment {} {}", self.proof_index, i), x)
            })
            .collect::<Vec<AstPointRc<C>>>();

        let gamma = transcript.squeeze_challenge();

        let lookup_permu_z_commitments =
            transcript.read_n_points(self.vk.num_lookups + self.vk.num_permutation_z_polys);

        let alpha = transcript.squeeze_challenge();
        let num_vars = self.vk.num_vars;
        let degree = self.vk.expression.degree();

        let ys = transcript.squeeze_n_challenges(num_vars);
        let protocol_challenges = [beta, gamma, alpha];

        //verify zero check
        let (sumcheck_msgs, sumcheck_challenges) = {
            let mut msgs = Vec::with_capacity(num_vars);
            let mut challenges = Vec::with_capacity(num_vars);
            for _ in 0..num_vars {
                // n-degree poly need n+1 sample points
                msgs.push(transcript.read_n_scalars(degree + 1));
                //get each round a challenge
                challenges.push(transcript.squeeze_challenge());
            }
            (msgs, challenges)
        };
        //verify received sumcheck msgs and get final eval at all challenges that f(r0,r1,r2..)
        let sumcheck_eval = verify_zero_sumcheck(&sumcheck_msgs, &sumcheck_challenges, degree);

        let fixed_commits = self
            .vk
            .preprocess_comms
            .iter()
            .map(|p| pconst!(*p))
            .collect::<Vec<_>>();
        let permut_commits = self
            .vk
            .permutation_comms
            .iter()
            .map(|p| pconst!(*p))
            .collect::<Vec<_>>();
        let comms = chain![
            &instance_dummy,
            &fixed_commits,
            &advice_commitments,
            &permut_commits,
            &lookup_m_commitments,
            &lookup_permu_z_commitments,
        ]
        .collect::<Vec<_>>();

        let mut query_evals = BTreeMap::new();
        let querys = pcs_query(&self.vk.expression, self.vk.num_instances);

        // calc instances evals
        let instance_query = instance_evals(
            num_vars,
            &self.vk.expression,
            &instances,
            &sumcheck_challenges,
        );
        for (q, e) in instance_query.iter() {
            query_evals.insert(*q, e.clone());
        }

        let mut query_commit_cur = vec![];
        let mut query_eval_cur = vec![];
        let mut query_eval_rot = vec![];

        for (i, q) in querys.iter().enumerate() {
            let eval = transcript.read_scalar();
            query_evals.insert(*q, eval.clone());

            if q.rotation() == Rotation::cur() {
                let commit = CommitQuery {
                    key: format!("{}commits{}", self.key, i),
                    commitment: Some(comms[q.poly()].clone()),
                    eval: None,
                };
                let eval = CommitQuery {
                    key: format!("{}evals_cur{}", self.key, i),
                    commitment: None,
                    eval: Some(eval.clone()),
                };
                query_commit_cur.push(commit!(Rc::new(commit)));
                query_eval_cur.push(eval!(Rc::new(eval)));
            } else {
                let eval = CommitQuery {
                    key: format!("{}evals_rot{}", self.key, i),
                    commitment: None,
                    eval: Some(eval.clone()),
                };
                query_eval_rot.push(eval!(Rc::new(eval)));
            }
        }
        //arrange sequence, keep all cur in head of rotation
        query_eval_cur.append(&mut query_eval_rot);

        // Expression evaluation vs. sumcheck evaluation:
        //
        // - sumcheck: compose all polynomials into one virtual polynomial via the expression,
        //   then evaluate it on the challenges.
        // - expression_eval: first evaluate each polynomial on the challenges,
        //   then combine the results according to the expression.
        //
        // expression_eval ensures that sumcheck is performed on the correct expression
        // by validating consistency with the polynomial evaluations.
        let expression_eval = evaluate_expression::<_, Lexical>(
            &self.vk.expression,
            num_vars,
            &query_evals,
            &protocol_challenges,
            &[&ys],
            &sumcheck_challenges,
        );

        let ell = querys.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_n_challenges(ell);
        //TODO: how about replacing eq_y with pow(y) as halo2?
        let eq_xt = eq_xy(&t);

        // the all rotated poly composed commitment
        let rotate_poly_commit = transcript.read_point();
        let rot_poly_comm = commit!(Rc::new(CommitQuery {
            key: format!("{}_rotate_poly_commit", self.key),
            commitment: Some(rotate_poly_commit.clone()),
            eval: None,
        }));
        let quotient_comms = transcript.read_n_points(num_vars);

        let quotient_comms = quotient_comms
            .iter()
            .enumerate()
            .map(|(i, q)| {
                Rc::new(CommitQuery {
                    key: format!("{}_quotient_poly_commit_{}", self.key, i),
                    commitment: Some(q.clone()),
                    eval: None,
                })
            })
            .collect::<Vec<_>>();
        let y = transcript.squeeze_challenge();

        let q_hat_comm = transcript.read_point();
        let q_hat_comm = commit!(Rc::new(CommitQuery {
            key: format!("{}_q_hat_comm", self.key),
            commitment: Some(q_hat_comm.clone()),
            eval: None,
        }));

        let x = transcript.squeeze_challenge();
        let z = transcript.squeeze_challenge();
        let (eval_scalar, q_scalars) =
            eval_and_quotient_scalars(y, x.clone(), z.clone(), &sumcheck_challenges);

        // quotient of kzg, proof
        let pi = transcript.read_point();
        let pi = Rc::new(CommitQuery {
            key: format!("{}pi", self.key),
            commitment: Some(pi),
            eval: None,
        });

        // compose all poly commitments(cur and rotated)
        let f_commit = query_commit_cur
            .iter()
            .zip(eq_xt.iter())
            .fold(rot_poly_comm, |acc, (e, t)| {
                acc + scalar!(t.clone()) * e.clone()
            });
        let f_eval = query_eval_cur
            .iter()
            .zip(eq_xt.iter())
            .fold(scalar!(sconst!(C::ScalarExt::zero())), |acc, (e, t)| {
                acc + scalar!(t.clone()) * e.clone()
            });

        // let scalars = chain![[one(),      z,        eval_scalar * eval, x],  q_scalars].collect_vec();
        // let bases   = chain![[q_hat_comm, f_commit, vp.g1(),            pi], q_comms].collect_vec();
        let t = scalar!(z) * f_commit
            + q_hat_comm
            + scalar!(eval_scalar) * f_eval
            + scalar!(x) * commit!(pi.clone())
            //embed equal-checking for (expression_eval,sumcheck_eval) in pairing checking
            //if expression_eval-sumcheck_eval==0, no impact to paring, if !=0, pairing fail
            + scalar!(expression_eval-sumcheck_eval);

        //[w_x(pi),s_g2],[w_g(pi+witness),-g2]
        let w_g = q_scalars
            .iter()
            .zip(quotient_comms.iter())
            .fold(t, |acc, (s, q)| {
                acc + scalar!(s.clone()) * commit!(q.clone())
            });
        let w_x = commit!(pi);

        (
            MultiOpenProof { w_x, w_g },
            advice_commitments,
            advice_cross_terms_commitments,
            transcript,
        )
    }
}
