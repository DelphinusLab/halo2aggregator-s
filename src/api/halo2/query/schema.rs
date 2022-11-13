use super::EvaluationQuerySchema;
use super::EvaluationQuerySchemaRc;
use halo2_proofs::arithmetic::CurveAffine;
use std::ops::Add;
use std::ops::Mul;
use std::rc::Rc;

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
