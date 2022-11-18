use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use std::ops::Add;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Sub;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq)]
pub enum AstScalar<C: CurveAffine> {
    FromConst(C::ScalarExt),
    FromTranscript(Rc<AstTranscript<C>>),
    FromChallenge(Rc<AstTranscript<C>>),
    Add(Rc<Self>, Rc<Self>),
    Sub(Rc<Self>, Rc<Self>),
    Mul(Rc<Self>, Rc<Self>),
    Div(Rc<Self>, Rc<Self>),
    Pow(Rc<Self>, u32),
    CheckPoint(String, Rc<Self>), // for debug
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct AstScalarRc<C: CurveAffine>(pub Rc<AstScalar<C>>);

#[derive(Debug, PartialEq, Eq)]
pub enum AstPoint<C: CurveAffine> {
    FromConst(C),
    FromTranscript(Rc<AstTranscript<C>>),
    FromInstance(usize, usize),
    Multiexp(Vec<(Rc<Self>, Rc<AstScalar<C>>)>),
    CheckPoint(String, Rc<Self>), // for debug
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct AstPointRc<C: CurveAffine>(pub Rc<AstPoint<C>>);

#[macro_export]
macro_rules! sconst {
    ($scalar:expr) => {
        AstScalarRc(Rc::new(AstScalar::FromConst($scalar)))
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
    ($proof_idx:expr, $instance_idx:expr) => {
        AstPointRc(Rc::new(AstPoint::FromInstance($proof_idx, $instance_idx)))
    };
}

#[macro_export]
macro_rules! pconst {
    ($instance_idx:expr) => {
        AstPointRc(Rc::new(AstPoint::FromConst($instance_idx)))
    };
}

#[macro_export]
macro_rules! pcheckpoint {
    ($tag:expr, $v:expr) => {
        AstPointRc(Rc::new(AstPoint::CheckPoint($tag, $v.0)))
    };
}

#[macro_export]
macro_rules! scheckpoint {
    ($tag:expr, $v:expr) => {
        AstScalarRc(Rc::new(AstScalar::CheckPoint($tag, $v.0)))
    };
}

impl<C: CurveAffine> AstScalar<C> {
    pub fn is_const_zero(&self) -> bool {
        match self {
            AstScalar::FromConst(v) => v == &C::ScalarExt::zero(),
            _ => false,
        }
    }

    pub fn is_const_one(&self) -> bool {
        match self {
            AstScalar::FromConst(v) => v == &C::ScalarExt::one(),
            _ => false,
        }
    }
}

impl<C: CurveAffine> Add<AstScalarRc<C>> for AstScalarRc<C> {
    type Output = AstScalarRc<C>;

    fn add(self, rhs: AstScalarRc<C>) -> Self::Output {
        let l: &AstScalar<C> = self.0.as_ref();
        let r: &AstScalar<C> = rhs.0.as_ref();
        match (l, r) {
            (AstScalar::FromConst(a), AstScalar::FromConst(b)) => {
                sconst!(*a + *b)
            }
            (AstScalar::FromConst(a), _) => {
                if a == &C::ScalarExt::zero() {
                    rhs
                } else {
                    AstScalarRc(Rc::new(AstScalar::Add(self.0, rhs.0)))
                }
            }
            (_, AstScalar::FromConst(b)) => {
                if b == &C::ScalarExt::zero() {
                    self
                } else {
                    AstScalarRc(Rc::new(AstScalar::Add(self.0, rhs.0)))
                }
            }
            _ => AstScalarRc(Rc::new(AstScalar::Add(self.0, rhs.0))),
        }
    }
}

impl<C: CurveAffine> Sub<AstScalarRc<C>> for AstScalarRc<C> {
    type Output = AstScalarRc<C>;

    fn sub(self, rhs: AstScalarRc<C>) -> Self::Output {
        let l: &AstScalar<C> = self.0.as_ref();
        let r: &AstScalar<C> = rhs.0.as_ref();
        match (l, r) {
            (AstScalar::FromConst(a), AstScalar::FromConst(b)) => {
                sconst!(*a - *b)
            }
            (_, AstScalar::FromConst(b)) => {
                if b == &C::ScalarExt::zero() {
                    self
                } else {
                    AstScalarRc(Rc::new(AstScalar::Sub(self.0, rhs.0)))
                }
            }
            _ => AstScalarRc(Rc::new(AstScalar::Sub(self.0, rhs.0))),
        }
    }
}

impl<C: CurveAffine> Div<AstScalarRc<C>> for AstScalarRc<C> {
    type Output = AstScalarRc<C>;

    fn div(self, rhs: AstScalarRc<C>) -> Self::Output {
        let l: &AstScalar<C> = self.0.as_ref();
        let r: &AstScalar<C> = rhs.0.as_ref();
        match (l, r) {
            (AstScalar::FromConst(a), AstScalar::FromConst(b)) => {
                sconst!(*a * b.invert().unwrap())
            }
            (AstScalar::FromConst(a), _) => {
                if a == &C::ScalarExt::zero() {
                    sconst!(C::ScalarExt::zero())
                } else {
                    AstScalarRc(Rc::new(AstScalar::Div(self.0, rhs.0)))
                }
            }
            _ => AstScalarRc(Rc::new(AstScalar::Div(self.0, rhs.0))),
        }
    }
}

impl<C: CurveAffine> Mul<AstScalarRc<C>> for AstScalarRc<C> {
    type Output = AstScalarRc<C>;

    fn mul(self, rhs: AstScalarRc<C>) -> Self::Output {
        let l: &AstScalar<C> = self.0.as_ref();
        let r: &AstScalar<C> = rhs.0.as_ref();
        match (l, r) {
            (AstScalar::FromConst(a), AstScalar::FromConst(b)) => {
                sconst!(*a * *b)
            }
            (_, AstScalar::FromConst(b)) => {
                if b == &C::ScalarExt::zero() {
                    sconst!(C::ScalarExt::zero())
                } else if b == &C::ScalarExt::one() {
                    self
                } else {
                    AstScalarRc(Rc::new(AstScalar::Mul(self.0, rhs.0)))
                }
            }
            (AstScalar::FromConst(a), _) => {
                if a == &C::ScalarExt::zero() {
                    sconst!(C::ScalarExt::zero())
                } else if a == &C::ScalarExt::one() {
                    rhs
                } else {
                    AstScalarRc(Rc::new(AstScalar::Mul(self.0, rhs.0)))
                }
            }
            _ => AstScalarRc(Rc::new(AstScalar::Mul(self.0, rhs.0))),
        }
    }
}

macro_rules! define_scalar_ops {
    ($t:ident, $f:ident, $symbo: tt) => {
        impl<C: CurveAffine> $t<&AstScalarRc<C>> for AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: &AstScalarRc<C>) -> Self::Output {
                self $symbo rhs.clone()
            }
        }
        impl<C: CurveAffine> $t<AstScalarRc<C>> for &AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: AstScalarRc<C>) -> Self::Output {
                self.clone() $symbo rhs
            }
        }
        impl<C: CurveAffine> $t<&AstScalarRc<C>> for &AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: &AstScalarRc<C>) -> Self::Output {
                self.clone() $symbo rhs.clone()
            }
        }
    };
}

define_scalar_ops!(Add, add, +);
define_scalar_ops!(Sub, sub, -);
define_scalar_ops!(Div, div, /);
define_scalar_ops!(Mul, mul, *);
