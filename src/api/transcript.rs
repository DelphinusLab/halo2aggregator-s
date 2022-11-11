use super::arith::AstPoint;
use super::arith::AstScalar;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

pub enum AstTranscript<C: CurveAffine> {
    CommonScalar(Rc<Self>, Rc<AstScalar<C>>),
    CommonPoint(Rc<Self>, Rc<AstPoint<C>>),
    Squeeze(Rc<Self>),
}
