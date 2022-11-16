use super::arith::AstPoint;
use super::arith::AstPointRc;
use super::arith::AstScalar;
use super::arith::AstScalarRc;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq)]
pub enum AstTranscript<C: CurveAffine> {
    ReadScalar(Rc<Self>),
    ReadPoint(Rc<Self>),
    CommonScalar(Rc<Self>, Rc<AstScalar<C>>),
    CommonPoint(Rc<Self>, Rc<AstPoint<C>>),
    SqueezeChallenge(Rc<Self>),
    Init,
}

pub(crate) trait AstTranscriptReader<C: CurveAffine> {
    fn common_scalar(self, s: AstScalarRc<C>) -> Self;
    fn common_point(self, p: AstPointRc<C>) -> Self;
    fn read_scalar(&mut self) -> AstScalarRc<C>;
    fn read_n_scalars(&mut self, n: usize) -> Vec<AstScalarRc<C>>;
    fn read_point(&mut self) -> AstPointRc<C>;
    fn read_n_points(&mut self, n: usize) -> Vec<AstPointRc<C>>;
    fn squeeze_challenge(&mut self) -> AstScalarRc<C>;
}

impl<C: CurveAffine> AstTranscriptReader<C> for Rc<AstTranscript<C>> {
    fn common_scalar(self, s: AstScalarRc<C>) -> Self {
        Rc::new(AstTranscript::CommonScalar(self, s.0))
    }

    fn common_point(self, p: AstPointRc<C>) -> Self {
        Rc::new(AstTranscript::CommonPoint(self, p.0))
    }

    fn read_scalar(&mut self) -> AstScalarRc<C> {
        *self = Rc::new(AstTranscript::ReadScalar(self.clone()));
        AstScalarRc(Rc::new(AstScalar::FromTranscript(self.clone())))
    }

    fn read_n_scalars(&mut self, n: usize) -> Vec<AstScalarRc<C>> {
        (0..n).map(|_| self.read_scalar()).collect()
    }

    fn read_point(&mut self) -> AstPointRc<C> {
        *self = Rc::new(AstTranscript::ReadPoint(self.clone()));
        AstPointRc(Rc::new(AstPoint::FromTranscript(self.clone())))
    }

    fn read_n_points(&mut self, n: usize) -> Vec<AstPointRc<C>> {
        (0..n).map(|_| self.read_point()).collect()
    }

    fn squeeze_challenge(&mut self) -> AstScalarRc<C> {
        *self = Rc::new(AstTranscript::SqueezeChallenge(self.clone()));
        AstScalarRc(Rc::new(AstScalar::FromChallenge(self.clone())))
    }
}
