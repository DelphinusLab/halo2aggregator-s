use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

#[derive(Debug)]
pub enum AstScalar<C: CurveAffine> {
    FromConst(C::ScalarExt),
    FromTranscript(Rc<AstTranscript<C>>),
    FromChallenge(Rc<AstTranscript<C>>),
    Add(Rc<Self>, Rc<Self>),
    Mul(Rc<Self>, Rc<Self>),
    Div(Rc<Self>, Rc<Self>),
}

#[derive(Debug)]
pub enum AstPoint<C: CurveAffine> {
    FromConst(C),
    FromTranscript(Rc<AstTranscript<C>>),
    FromInstance(usize),
    Multiexp(Vec<(Rc<Self>, Rc<AstScalar<C>>)>),
}

#[macro_export]
macro_rules! sconst {
    ($scalar:expr) => {
        Rc::new(AstScalar::FromConst($scalar))
    };
}

#[macro_export]
macro_rules! pinstance {
    ($instance_idx:expr) => {
        Rc::new(AstPoint::FromInstance($instance_idx))
    };
}

#[macro_export]
macro_rules! ptranscript {
    ($transcript: expr) => {{
        let p = Rc::new(AstPoint::FromTranscript($transcript));
        let t = Rc::new(AstTranscript::CommonPoint($transcript, p.clone()));
        (p, t)
    }};
}
