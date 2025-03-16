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
    Mul(Rc<Self>, Rc<Self>, bool), // bool if for challenge group optimization
    Div(Rc<Self>, Rc<Self>),
    Pow(Rc<Self>, u32),
    CheckPoint(String, Rc<Self>), // for debug
}

impl<C: CurveAffine> AstScalar<C> {
    pub fn is_challenge_group(&self) -> bool {
        match self {
            AstScalar::FromChallenge(_) => true,
            AstScalar::Mul(_, _, x) => *x,
            AstScalar::CheckPoint(_, x) => x.is_challenge_group(),
            _ => false,
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct AstScalarRc<C: CurveAffine>(pub Rc<AstScalar<C>>);

#[derive(Debug, PartialEq, Eq)]
pub enum AstPoint<C: CurveAffine> {
    FromConst(C),
    FromTranscript(Rc<AstTranscript<C>>),
    FromInstance(usize, usize),
    MultiExp(Vec<(Rc<Self>, Rc<AstScalar<C>>)>, usize), // msm group: usize
    CheckPoint(String, Rc<Self>),                       // for debug
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
    pub fn check_const_and_get(&self) -> Option<C::ScalarExt> {
        match self {
            AstScalar::FromConst(v) => Some(*v),
            _ => None,
        }
    }

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
                return sconst!(*a * *b);
            }
            (_, AstScalar::FromConst(b)) => {
                if b == &C::ScalarExt::zero() {
                    return sconst!(C::ScalarExt::zero());
                } else if b == &C::ScalarExt::one() {
                    return self;
                }
            }
            (AstScalar::FromConst(a), _) => {
                if a == &C::ScalarExt::zero() {
                    return sconst!(C::ScalarExt::zero());
                } else if a == &C::ScalarExt::one() {
                    return rhs;
                }
            }
            // Specific Optimization
            (AstScalar::Mul(a, b, is_challenge_group), c) => {
                // Same group
                if b == &rhs.0 && a != b {
                    return AstScalarRc(a.clone())
                        * (AstScalarRc(b.clone()) * AstScalarRc(b.clone()));
                }
                // Challenge group
                if !is_challenge_group && b.is_challenge_group() && c.is_challenge_group() {
                    return AstScalarRc(a.clone()) * (AstScalarRc(b.clone()) * rhs);
                }
            }

            _ => {}
        }

        let is_challenge_group = self.0.is_challenge_group() && rhs.0.is_challenge_group();

        AstScalarRc(Rc::new(AstScalar::Mul(self.0, rhs.0, is_challenge_group)))
    }
}

macro_rules! define_scalar_ops {
    ($t:ident, $f:ident, $symbol: tt) => {
        impl<C: CurveAffine> $t<&AstScalarRc<C>> for AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: &AstScalarRc<C>) -> Self::Output {
                self $symbol rhs.clone()
            }
        }
        impl<C: CurveAffine> $t<AstScalarRc<C>> for &AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: AstScalarRc<C>) -> Self::Output {
                self.clone() $symbol rhs
            }
        }
        impl<C: CurveAffine> $t<&AstScalarRc<C>> for &AstScalarRc<C> {
            type Output = AstScalarRc<C>;

            fn $f(self, rhs: &AstScalarRc<C>) -> Self::Output {
                self.clone() $symbol rhs.clone()
            }
        }
    };
}

define_scalar_ops!(Add, add, +);
define_scalar_ops!(Sub, sub, -);
define_scalar_ops!(Div, div, /);
define_scalar_ops!(Mul, mul, *);
