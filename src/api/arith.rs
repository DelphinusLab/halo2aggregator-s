use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

pub enum AstScalar<C: CurveAffine> {
    Const(C::ScalarExt),
    FromTranscript(Rc<AstTranscript<C>>),
    FromSqueeze(Rc<AstTranscript<C>>),
    Add(Rc<Self>, Rc<Self>),
    Mul(Rc<Self>, Rc<Self>),
    Div(Rc<Self>, Rc<Self>),
}

pub enum AstPoint<C: CurveAffine> {
    Const(C),
    FromTranscript(Rc<AstTranscript<C>>),
    MSM(Vec<(Rc<Self>, Rc<AstScalar<C>>)>),
}
