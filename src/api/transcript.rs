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

pub(crate) trait AstTranscriptReader<C: CurveAffine> {
    fn read_scalar(&mut self) -> Rc<AstScalar<C>>;
    fn read_n_scalars(&mut self, n: usize) -> Vec<Rc<AstScalar<C>>>;
    fn read_point(&mut self) -> Rc<AstPoint<C>>;
    fn read_n_points(&mut self, n: usize) -> Vec<Rc<AstPoint<C>>>;
    fn squeeze_challenge(&mut self) -> Rc<AstScalar<C>>;
}

impl<C: CurveAffine> AstTranscriptReader<C> for Rc<AstTranscript<C>> {
    fn read_scalar(&mut self) -> Rc<AstScalar<C>> {
        let p = Rc::new(AstScalar::FromTranscript(self.clone()));
        let t = Rc::new(AstTranscript::CommonScalar(self.clone(), p.clone()));
        *self = t;
        p
    }

    fn read_n_scalars(&mut self, n: usize) -> Vec<Rc<AstScalar<C>>> {
        (0..n).map(|_| self.read_scalar()).collect()
    }

    fn read_point(&mut self) -> Rc<AstPoint<C>> {
        let p = Rc::new(AstPoint::FromTranscript(self.clone()));
        let t = Rc::new(AstTranscript::CommonPoint(self.clone(), p.clone()));
        *self = t;
        p
    }

    fn read_n_points(&mut self, n: usize) -> Vec<Rc<AstPoint<C>>> {
        (0..n).map(|_| self.read_point()).collect()
    }

    fn squeeze_challenge(&mut self) -> Rc<AstScalar<C>> {
        let s = Rc::new(AstScalar::FromChallenge(self.clone()));
        let t = Rc::new(AstTranscript::SqueezeChallenge(self.clone()));
        *self = t;
        s
    }
}
