use crate::api::arith::AstPoint;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::commit;
use crate::eval;
use crate::pconst;
use crate::scheckpoint;
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use std::collections::BTreeMap;
use std::ops::Add;
use std::ops::Mul;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub struct CommitQuery<C: CurveAffine> {
    pub key: String,
    pub commitment: Option<AstPointRc<C>>,
    pub eval: Option<AstScalarRc<C>>,
}

impl<C: CurveAffine> PartialEq for CommitQuery<C> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

#[derive(Clone, Debug)]
pub enum EvaluationQuerySchema<C: CurveAffine> {
    Commitment(Rc<CommitQuery<C>>),
    Eval(Rc<CommitQuery<C>>),
    Scalar(AstScalarRc<C>),
    Add(Rc<Self>, Rc<Self>, bool), // bool indicates whether contains commitment
    Mul(Rc<Self>, Rc<Self>, bool), // bool indicates whether contains commitment
    CheckPoint(String, Rc<Self>),
}

impl<C: CurveAffine> EvaluationQuerySchema<C> {
    pub fn get_eval(&self) -> AstScalarRc<C> {
        match self {
            EvaluationQuerySchema::Commitment(x) => {
                x.eval.clone().unwrap_or(sconst!(C::ScalarExt::zero()))
            }
            EvaluationQuerySchema::Eval(x) => x.eval.clone().unwrap(),
            EvaluationQuerySchema::Scalar(s) => s.clone(),
            EvaluationQuerySchema::Add(l, r, _) => l.get_eval() + r.get_eval(),
            EvaluationQuerySchema::Mul(l, r, _) => l.get_eval() * r.get_eval(),
            EvaluationQuerySchema::CheckPoint(_, x) => x.get_eval(),
        }
    }
}

impl<C: CurveAffine> PartialEq for EvaluationQuerySchema<C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (EvaluationQuerySchema::Commitment(l), Self::Commitment(r)) => l.eq(r),
            (Self::Eval(l), Self::Eval(r)) => l.eq(r),
            (Self::Scalar(l), Self::Scalar(r)) => Rc::eq(&l.0, &r.0),
            (Self::Add(l1, l2, _), Self::Add(r1, r2, _)) => l1.eq(r1) && l2.eq(r2),
            (Self::Mul(l1, l2, _), Self::Mul(r1, r2, _)) => l1.eq(r1) && l2.eq(r2),
            (Self::CheckPoint(_, l), Self::CheckPoint(_, r)) => l.eq(r),
            _ => false,
        }
    }
}

pub fn replace_commitment<C: CurveAffine>(
    mut target: Rc<EvaluationQuerySchema<C>>,
    from_key: &String,
    to_key: &String,
    p: &AstPointRc<C>,
) -> (Rc<EvaluationQuerySchema<C>>, bool) {
    let mut replaced = false;
    match target.as_ref() {
        EvaluationQuerySchema::Commitment(a) => {
            if from_key == &a.key {
                let mut a = Rc::as_ref(a).clone();
                a.commitment = Some(p.clone());
                a.key = to_key.to_owned();
                target = Rc::new(EvaluationQuerySchema::Commitment(Rc::new(a)));
                replaced = true;
            }
        }
        EvaluationQuerySchema::Add(a, b, true) => {
            let (a, ra) = replace_commitment(a.clone(), from_key, to_key, p);
            let (b, rb) = replace_commitment(b.clone(), from_key, to_key, p);
            if ra || rb {
                target = Rc::new(EvaluationQuerySchema::Add(a, b, true));
                replaced = true;
            }
        }
        EvaluationQuerySchema::Mul(a, b, true) => {
            let (a, ra) = replace_commitment(a.clone(), from_key, to_key, p);
            let (b, rb) = replace_commitment(b.clone(), from_key, to_key, p);
            if ra || rb {
                target = Rc::new(EvaluationQuerySchema::Mul(a, b, true));
                replaced = true;
            }
        }
        EvaluationQuerySchema::CheckPoint(s, a) => {
            let (a, ra) = replace_commitment(a.clone(), from_key, to_key, p);
            if ra {
                target = Rc::new(EvaluationQuerySchema::CheckPoint(s.to_string(), a));
                replaced = true;
            }
        }
        _ => {}
    }
    (target, replaced)
}

#[repr(transparent)]
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationQuerySchemaRc<C: CurveAffine>(pub Rc<EvaluationQuerySchema<C>>);

#[derive(Clone, Debug)]
pub struct EvaluationQuery<C: CurveAffine> {
    pub point: AstScalarRc<C>,
    pub rotation: i32,
    pub commitment: EvaluationQuerySchemaRc<C>,
    pub eval: Option<EvaluationQuerySchemaRc<C>>,
}

impl<C: CurveAffine> EvaluationQuery<C> {
    pub fn new(
        rotation: i32,
        point: AstScalarRc<C>,
        key: String,
        commitment: AstPointRc<C>,
        eval: AstScalarRc<C>,
    ) -> Self {
        let c = Rc::new(CommitQuery {
            key,
            commitment: Some(commitment),
            eval: Some(eval),
        });

        EvaluationQuery {
            point,
            rotation,
            commitment: commit!(c.clone()),
            eval: Some(eval!(c)),
        }
    }

    pub fn new_with_query(
        rotation: i32,
        point: AstScalarRc<C>,
        commitment: EvaluationQuerySchemaRc<C>,
        eval: EvaluationQuerySchemaRc<C>,
    ) -> Self {
        EvaluationQuery {
            rotation,
            point,
            commitment,
            eval: Some(eval),
        }
    }
}

#[macro_export]
macro_rules! commit {
    ($x:expr) => {
        EvaluationQuerySchemaRc(Rc::new(
            crate::api::halo2::query::EvaluationQuerySchema::Commitment($x),
        ))
    };
}

#[macro_export]
macro_rules! eval {
    ($x:expr) => {
        EvaluationQuerySchemaRc(Rc::new(
            crate::api::halo2::query::EvaluationQuerySchema::Eval($x),
        ))
    };
}

#[macro_export]
macro_rules! scalar {
    ($x:expr) => {
        EvaluationQuerySchemaRc(Rc::new(
            crate::api::halo2::query::EvaluationQuerySchema::Scalar($x),
        ))
    };
}

#[macro_export]
macro_rules! echeckpoint {
    ($tag:expr, $x:expr) => {
        EvaluationQuerySchemaRc(Rc::new(
            crate::api::halo2::query::EvaluationQuerySchema::CheckPoint($tag, $x),
        ))
    };
}

impl<C: CurveAffine> EvaluationQuerySchema<C> {
    pub fn contains_commitment(&self) -> bool {
        match self {
            EvaluationQuerySchema::Commitment(_) => true,
            EvaluationQuerySchema::Eval(_) => false,
            EvaluationQuerySchema::Scalar(_) => false,
            EvaluationQuerySchema::Add(_, _, c) => *c,
            EvaluationQuerySchema::Mul(_, _, c) => *c,
            EvaluationQuerySchema::CheckPoint(_, s) => s.contains_commitment(),
        }
    }
}

impl<C: CurveAffine> Add<EvaluationQuerySchemaRc<C>> for EvaluationQuerySchemaRc<C> {
    type Output = EvaluationQuerySchemaRc<C>;
    fn add(self, other: EvaluationQuerySchemaRc<C>) -> Self::Output {
        let contains_commitment = self.0.contains_commitment() || other.0.contains_commitment();
        EvaluationQuerySchemaRc(Rc::new(EvaluationQuerySchema::Add(
            self.0,
            other.0,
            contains_commitment,
        )))
    }
}

impl<C: CurveAffine> Mul<EvaluationQuerySchemaRc<C>> for EvaluationQuerySchemaRc<C> {
    type Output = EvaluationQuerySchemaRc<C>;
    fn mul(self, other: EvaluationQuerySchemaRc<C>) -> Self::Output {
        let contains_commitment = self.0.contains_commitment() || other.0.contains_commitment();
        EvaluationQuerySchemaRc(Rc::new(EvaluationQuerySchema::Mul(
            self.0,
            other.0,
            contains_commitment,
        )))
    }
}

impl<C: CurveAffine> EvaluationQuerySchemaRc<C> {
    pub fn eval(self, g1: C, msm_index: usize) -> AstPointRc<C> {
        let (pl, s) = self.eval_prepare(sconst!(C::ScalarExt::one()));
        let g1_msm = if let Some(v) = s.0.check_const_and_get() {
            if v.is_zero_vartime() {
                vec![]
            } else {
                use halo2_proofs::pairing::group::Curve;
                vec![(
                    pconst!((g1 * v).to_affine()).0,
                    sconst!(C::ScalarExt::one()).0,
                )]
            }
        } else {
            vec![(
                pconst!(g1).0,
                (scheckpoint!("msm g1 scalar".to_owned(), s)).0,
            )]
        };

        AstPointRc(Rc::new(AstPoint::MultiExp(
            vec![
                g1_msm,
                pl.into_values()
                    .into_iter()
                    .map(|(p, s)| (p.0, s.0))
                    .collect::<Vec<_>>(),
            ]
            .concat(),
            msm_index,
        )))
    }

    /*
    fn eval_prepare(
        self,
    ) -> (
        BTreeMap<String, (AstPointRc<C>, AstScalarRc<C>)>,
        AstScalarRc<C>,
    ) {
        match self.0.as_ref() {
            EvaluationQuerySchema::Commitment(cq) => (
                BTreeMap::from_iter(
                    vec![(
                        cq.key.clone(),
                        (
                            cq.commitment.clone().unwrap(),
                            sconst!(C::ScalarExt::one()),
                        ),
                    )]
                    .into_iter(),
                ),
                sconst!(C::ScalarExt::zero()),
            ),
            EvaluationQuerySchema::Eval(cq) => (BTreeMap::new(), cq.eval.clone().unwrap()),
            EvaluationQuerySchema::Scalar(s) => (BTreeMap::new(), s.clone()),
            EvaluationQuerySchema::Add(l, r, _) => {
                let evaluated_l = EvaluationQuerySchemaRc(l.clone()).eval_prepare();
                let evaluated_r = EvaluationQuerySchemaRc(r.clone()).eval_prepare();

                let s = evaluated_l.1 + evaluated_r.1;
                let mut pl = evaluated_l.0;
                for (k, (p, sr)) in evaluated_r.0 {
                    if let Some(sl) = pl.get_mut(&k) {
                        assert!(Rc::ptr_eq(&sl.0 .0, &p.0));
                        sl.1 = &sl.1 + sr;
                    } else {
                        pl.insert(k, (p, sr));
                    }
                }
                (pl, s)
            }
            EvaluationQuerySchema::Mul(l, r, _) => {
                let (coeff, other) = if l.contains_commitment() {
                    (
                        EvaluationQuerySchemaRc(r.clone()).eval_prepare().1,
                        l.clone(),
                    )
                } else {
                    (
                        EvaluationQuerySchemaRc(l.clone()).eval_prepare().1,
                        r.clone(),
                    )
                };

                let (mut pl, s) = EvaluationQuerySchemaRc(other).eval_prepare();
                for (_, (_, ps)) in pl.iter_mut() {
                    *ps = ps.clone() * coeff.clone();
                }
                (pl, s * coeff)
            }
            EvaluationQuerySchema::CheckPoint(tag, s) => {
                let (pl, s) = EvaluationQuerySchemaRc(s.clone()).eval_prepare();
                (pl, scheckpoint!(tag.clone(), s))
            }
        }
    }
    */

    fn eval_prepare(
        self,
        coeff: AstScalarRc<C>,
    ) -> (
        BTreeMap<String, (AstPointRc<C>, AstScalarRc<C>)>,
        AstScalarRc<C>,
    ) {
        match self.0.as_ref() {
            EvaluationQuerySchema::Commitment(cq) => (
                BTreeMap::from_iter(
                    vec![(cq.key.clone(), (cq.commitment.clone().unwrap(), coeff))].into_iter(),
                ),
                sconst!(C::ScalarExt::zero()),
            ),
            EvaluationQuerySchema::Eval(cq) => (BTreeMap::new(), coeff * cq.eval.clone().unwrap()),
            EvaluationQuerySchema::Scalar(s) => (BTreeMap::new(), coeff * s),
            EvaluationQuerySchema::Add(l, r, _) => {
                let evaluated_l = EvaluationQuerySchemaRc(l.clone()).eval_prepare(coeff.clone());
                let evaluated_r = EvaluationQuerySchemaRc(r.clone()).eval_prepare(coeff);

                let s = evaluated_l.1 + evaluated_r.1;
                let mut pl = evaluated_l.0;
                for (k, (p, sr)) in evaluated_r.0 {
                    if let Some(sl) = pl.get_mut(&k) {
                        assert!(Rc::ptr_eq(&sl.0 .0, &p.0));
                        sl.1 = &sl.1 + sr;
                    } else {
                        pl.insert(k, (p, sr));
                    }
                }
                (pl, s)
            }
            EvaluationQuerySchema::Mul(l, r, _) => {
                let (coeff, other) = if l.contains_commitment() {
                    (
                        EvaluationQuerySchemaRc(r.clone()).eval_prepare(coeff).1,
                        l.clone(),
                    )
                } else {
                    (
                        EvaluationQuerySchemaRc(l.clone()).eval_prepare(coeff).1,
                        r.clone(),
                    )
                };

                EvaluationQuerySchemaRc(other).eval_prepare(coeff)
            }
            EvaluationQuerySchema::CheckPoint(_, s) => {
                EvaluationQuerySchemaRc(s.clone()).eval_prepare(coeff)
            }
        }
    }
}
