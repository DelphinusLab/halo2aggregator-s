use super::arith::AstPoint;
use super::arith::AstScalar;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

#[derive(Debug)]
pub enum AstTranscript<C: CurveAffine> {
    CommonScalar(Rc<Self>, Rc<AstScalar<C>>),
    CommonPoint(Rc<Self>, Rc<AstPoint<C>>),
    SqueezeChallenge(Rc<Self>),
    Init,
}

#[macro_export]
macro_rules! common_scalar {
    ($transcript: expr, $scalar:expr) => {
        Rc::new(AstTranscript::CommonScalar($transcript, $scalar))
    };
}

#[macro_export]
macro_rules! common_point {
    ($transcript: expr, $scalar:expr) => {
        Rc::new(AstTranscript::CommonPoint($transcript, $scalar))
    };
}
