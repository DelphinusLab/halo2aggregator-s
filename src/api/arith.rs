use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::CurveAffine;
use std::ops::Add;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Sub;
use std::rc::Rc;

#[derive(Debug)]
pub enum AstScalar<C: CurveAffine> {
    FromConst(C::ScalarExt),
    FromTranscript(Rc<AstTranscript<C>>),
    FromChallenge(Rc<AstTranscript<C>>),
    Add(Rc<Self>, Rc<Self>),
    Sub(Rc<Self>, Rc<Self>),
    Mul(Rc<Self>, Rc<Self>),
    Div(Rc<Self>, Rc<Self>),
    Pow(Rc<Self>, u32),
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct AstScalarRc<C: CurveAffine>(pub Rc<AstScalar<C>>);

macro_rules! define_scalar_ops {
    ($t:ident, $f:ident) => {
        impl<C: CurveAffine> $t<AstScalarRc<C>> for AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: AstScalarRc<C>) -> Self::Output {
                AstScalarRc(Rc::new(AstScalar::$t(self.0, rhs.0)))
            }
        }
        impl<C: CurveAffine> $t<&AstScalarRc<C>> for AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: &AstScalarRc<C>) -> Self::Output {
                AstScalarRc(Rc::new(AstScalar::$t(self.0, rhs.0.clone())))
            }
        }
        impl<C: CurveAffine> $t<AstScalarRc<C>> for &AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: AstScalarRc<C>) -> Self::Output {
                AstScalarRc(Rc::new(AstScalar::$t(self.0.clone(), rhs.0)))
            }
        }
        impl<C: CurveAffine> $t<&AstScalarRc<C>> for &AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: &AstScalarRc<C>) -> Self::Output {
                AstScalarRc(Rc::new(AstScalar::$t(self.0.clone(), rhs.0.clone())))
            }
        }
    };
}

define_scalar_ops!(Add, add);
define_scalar_ops!(Sub, sub);
define_scalar_ops!(Div, div);
define_scalar_ops!(Mul, mul);

#[derive(Debug)]
pub enum AstPoint<C: CurveAffine> {
    FromConst(C),
    FromTranscript(Rc<AstTranscript<C>>),
    FromInstance(usize),
    Multiexp(Vec<(Rc<Self>, Rc<AstScalar<C>>)>),
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct AstPointRc<C: CurveAffine>(pub Rc<AstPoint<C>>);

#[macro_export]
macro_rules! sconst {
    ($scalar:expr) => {
        AstScalarRc(Rc::new(AstScalar::FromConst(C::ScalarExt::from($scalar))))
    };
}

#[macro_export]
macro_rules! spow {
    ($scalar:expr, $n:expr) => {
        AstScalarRc(Rc::new(AstScalar::Pow($scalar.0, $n)))
    };
}

#[macro_export]
macro_rules! pinstance {
    ($instance_idx:expr) => {
        AstPointRc(Rc::new(AstPoint::FromInstance($instance_idx)))
    };
}

#[macro_export]
macro_rules! pconst {
    ($instance_idx:expr) => {
        AstPointRc(Rc::new(AstPoint::FromConst($instance_idx)))
    };
}
