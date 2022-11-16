use super::arith::AstPoint;
use super::arith::AstPointRc;
use super::arith::AstScalar;
use super::arith::AstScalarRc;
use halo2_proofs::arithmetic::CurveAffine;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq)]
pub enum AstTranscript<C: CurveAffine> {
    ReadScalar(usize, Rc<Self>),
    ReadPoint(usize, Rc<Self>),
    CommonScalar(usize, Rc<Self>, Rc<AstScalar<C>>),
    CommonPoint(usize, Rc<Self>, Rc<AstPoint<C>>),
    SqueezeChallenge(usize, Rc<Self>),
    Init(usize),
}

pub(crate) trait AstTranscriptReader<C: CurveAffine> {
    fn proof_index(&self) -> usize;
    fn common_scalar(&mut self, s: AstScalarRc<C>);
    fn common_point(&mut self, p: AstPointRc<C>);
    fn read_scalar(&mut self) -> AstScalarRc<C>;
    fn read_n_scalars(&mut self, n: usize) -> Vec<AstScalarRc<C>>;
    fn read_point(&mut self) -> AstPointRc<C>;
    fn read_n_points(&mut self, n: usize) -> Vec<AstPointRc<C>>;
    fn squeeze_challenge(&mut self) -> AstScalarRc<C>;
}

impl<C: CurveAffine> AstTranscriptReader<C> for Rc<AstTranscript<C>> {
    fn proof_index(&self) -> usize {
        match self.as_ref() {
            AstTranscript::ReadScalar(idx, _) => *idx,
            AstTranscript::ReadPoint(idx, _) => *idx,
            AstTranscript::CommonScalar(idx, _, _) => *idx,
            AstTranscript::CommonPoint(idx, _, _) => *idx,
            AstTranscript::SqueezeChallenge(idx, _) => *idx,
            AstTranscript::Init(idx) => *idx,
        }
    }

    fn common_scalar(&mut self, s: AstScalarRc<C>) {
        *self = Rc::new(AstTranscript::CommonScalar(
            self.proof_index(),
            self.clone(),
            s.0,
        ))
    }

    fn common_point(&mut self, p: AstPointRc<C>) {
        *self = Rc::new(AstTranscript::CommonPoint(
            self.proof_index(),
            self.clone(),
            p.0,
        ))
    }

    fn read_scalar(&mut self) -> AstScalarRc<C> {
        *self = Rc::new(AstTranscript::ReadScalar(self.proof_index(), self.clone()));
        AstScalarRc(Rc::new(AstScalar::FromTranscript(self.clone())))
    }

    fn read_n_scalars(&mut self, n: usize) -> Vec<AstScalarRc<C>> {
        (0..n).map(|_| self.read_scalar()).collect()
    }

    fn read_point(&mut self) -> AstPointRc<C> {
        *self = Rc::new(AstTranscript::ReadPoint(self.proof_index(), self.clone()));
        AstPointRc(Rc::new(AstPoint::FromTranscript(self.clone())))
    }

    fn read_n_points(&mut self, n: usize) -> Vec<AstPointRc<C>> {
        (0..n).map(|_| self.read_point()).collect()
    }

    fn squeeze_challenge(&mut self) -> AstScalarRc<C> {
        *self = Rc::new(AstTranscript::SqueezeChallenge(
            self.proof_index(),
            self.clone(),
        ));
        AstScalarRc(Rc::new(AstScalar::FromChallenge(self.clone())))
    }
}
