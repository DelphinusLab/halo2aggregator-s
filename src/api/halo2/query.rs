use crate::api::arith::AstPoint;
use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalar;
use crate::api::arith::AstScalarRc;
use crate::commit;
use crate::eval;
use crate::pconst;
use crate::sconst;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use std::collections::HashMap;
use std::ops::Add;
use std::ops::Mul;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub struct CommitQuery<C: CurveAffine> {
    pub key: String,
    pub commitment: Option<AstPointRc<C>>,
    pub eval: Option<AstScalarRc<C>>,
}

#[derive(Clone, Debug)]
pub enum EvaluationQuerySchema<C: CurveAffine> {
    Commitment(Rc<CommitQuery<C>>),
    Eval(Rc<CommitQuery<C>>),
    Scalar(AstScalarRc<C>),
    Add(Rc<Self>, Rc<Self>, bool),
    Mul(Rc<Self>, Rc<Self>, bool),
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct EvaluationQuerySchemaRc<C: CurveAffine>(pub Rc<EvaluationQuerySchema<C>>);

#[derive(Clone, Debug)]
pub struct EvaluationQuery<C: CurveAffine> {
    pub point: AstScalarRc<C>,
    pub rotation: i32,
    pub s: EvaluationQuerySchemaRc<C>,
}

impl<C: CurveAffine> EvaluationQuery<C> {
    pub fn new(
        rotation: i32,
        point: AstScalarRc<C>,
        key: String,
        commitment: AstPointRc<C>,
        eval: AstScalarRc<C>,
    ) -> Self {
        let s = Rc::new(CommitQuery {
            key,
            commitment: Some(commitment),
            eval: Some(eval),
        });

        EvaluationQuery {
            point,
            rotation,
            s: commit!(s.clone()) + eval!(s),
        }
    }

    pub fn new_with_query(
        rotation: i32,
        point: AstScalarRc<C>,
        s: EvaluationQuerySchemaRc<C>,
    ) -> Self {
        EvaluationQuery { rotation, point, s }
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

impl<C: CurveAffine> EvaluationQuerySchema<C> {
    pub fn contains_commitment(&self) -> bool {
        match self {
            EvaluationQuerySchema::Commitment(_) => true,
            EvaluationQuerySchema::Eval(_) => false,
            EvaluationQuerySchema::Scalar(_) => false,
            EvaluationQuerySchema::Add(_, _, c) => *c,
            EvaluationQuerySchema::Mul(_, _, c) => *c,
        }
    }
}

impl<C: CurveAffine> Add<EvaluationQuerySchemaRc<C>> for EvaluationQuerySchemaRc<C> {
    type Output = EvaluationQuerySchemaRc<C>;
    fn add(self, other: EvaluationQuerySchemaRc<C>) -> Self::Output {
        let contains_commitment = self.0.contains_commitment() && other.0.contains_commitment();
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
        let contains_commitment = self.0.contains_commitment() && other.0.contains_commitment();
        EvaluationQuerySchemaRc(Rc::new(EvaluationQuerySchema::Mul(
            self.0,
            other.0,
            contains_commitment,
        )))
    }
}

impl<C: CurveAffine> EvaluationQuerySchemaRc<C> {
    pub fn eval(self, s_coeff: AstScalarRc<C>) -> AstPointRc<C> {
        let one = sconst!(C::ScalarExt::one());

        let (pl, s) = self.eval_prepare(one);
        AstPointRc(Rc::new(AstPoint::Multiexp(
            vec![
                vec![(pconst!(C::generator()).0, (s_coeff * s).0)],
                pl.into_values()
                    .into_iter()
                    .map(|(p, s)| (p.0, s.0))
                    .collect(),
            ]
            .concat(),
        )))
    }

    fn eval_prepare(
        self,
        coeff: AstScalarRc<C>,
    ) -> (
        HashMap<String, (AstPointRc<C>, AstScalarRc<C>)>,
        AstScalarRc<C>,
    ) {
        match self.0.as_ref() {
            EvaluationQuerySchema::Commitment(cq) => (
                HashMap::from_iter(
                    vec![(cq.key.clone(), (cq.commitment.clone().unwrap(), coeff))].into_iter(),
                ),
                sconst!(C::ScalarExt::zero()),
            ),
            EvaluationQuerySchema::Eval(cq) => (HashMap::new(), coeff * cq.eval.clone().unwrap()),
            EvaluationQuerySchema::Scalar(s) => (HashMap::new(), s * coeff),
            EvaluationQuerySchema::Add(l, r, _) => {
                let evaluated_l = EvaluationQuerySchemaRc(l.clone()).eval_prepare(coeff.clone());
                let evaluated_r = EvaluationQuerySchemaRc(r.clone()).eval_prepare(coeff.clone());

                let s = evaluated_l.1 + evaluated_r.1;
                let mut pl = evaluated_l.0;
                for (k, (p, sr)) in evaluated_r.0 {
                    if let Some(sl) = pl.get_mut(&k) {
                        sl.1 = &sl.1 + sr;
                    } else {
                        pl.insert(k, (p, sr));
                    }
                }
                (pl, s)
            }
            EvaluationQuerySchema::Mul(l, r, _) => {
                let (s, other) = if l.contains_commitment() {
                    (
                        EvaluationQuerySchemaRc(r.clone())
                            .eval_prepare(coeff.clone())
                            .1,
                        l.clone(),
                    )
                } else {
                    (
                        EvaluationQuerySchemaRc(l.clone())
                            .eval_prepare(coeff.clone())
                            .1,
                        r.clone(),
                    )
                };

                EvaluationQuerySchemaRc(other).eval_prepare(coeff * s)
            }
        }
    }
}
