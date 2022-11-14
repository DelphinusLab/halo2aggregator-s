use crate::api::arith::AstPointRc;
use crate::api::arith::AstScalarRc;
use crate::commit;
use crate::eval;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;
pub mod schema;

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
