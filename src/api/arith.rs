use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::CurveAffine;
use std::ops::Mul;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub enum AstScalar<C: CurveAffine> {
    FromConst(C::ScalarExt),
    FromTranscript(Rc<AstTranscript<C>>),
    FromChallenge(Rc<AstTranscript<C>>),
    Add(Rc<Self>, Rc<Self>),
    Mul(Rc<Self>, Rc<Self>),
    Div(Rc<Self>, Rc<Self>),
    Pow(Rc<Self>, u32),
}

impl<'a, C: CurveAffine> Mul<Rc<AstScalar<C>>> for &'a AstScalar<C> {
    type Output = Rc<AstScalar<C>>;

    fn mul(self, rhs: Rc<AstScalar<C>>) -> Self::Output {
        Rc::new(AstScalar::Mul(Rc::new(self.clone()), rhs))
    }
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
macro_rules! spow {
    ($scalar:expr, $n:expr) => {
        Rc::new(AstScalar::Pow($scalar, $n))
    };
}

#[macro_export]
macro_rules! pinstance {
    ($instance_idx:expr) => {
        Rc::new(AstPoint::FromInstance($instance_idx))
    };
}

#[macro_export]
macro_rules! pconst {
    ($instance_idx:expr) => {
        Rc::new(AstPoint::FromConst($instance_idx))
    };
}
