use crate::circuit_verifier::encode_point;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::Transcript;
use halo2_proofs::transcript::TranscriptRead;
use halo2_proofs::transcript::TranscriptWrite;
use plonkish_backend::util::transcript::FieldTranscript;
use plonkish_backend::util::transcript::FieldTranscriptRead;
use plonkish_backend::util::transcript::FieldTranscriptWrite;
use plonkish_backend::util::transcript::Transcript as PointTranscript;
use plonkish_backend::util::transcript::TranscriptRead as PointTranscriptRead;
use plonkish_backend::util::transcript::TranscriptWrite as PointTranscriptWrite;
use plonkish_backend::Error as HyperError;
use poseidon::Poseidon;
use std::io;
use std::marker::PhantomData;

pub const T: usize = 9;
pub const RATE: usize = 8;
pub const R_F: usize = 8;
pub const R_P: usize = 63;

pub const PREFIX_CHALLENGE: u64 = 0u64;
pub const PREFIX_POINT: u64 = 1u64;
pub const PREFIX_SCALAR: u64 = 2u64;

pub struct PoseidonEncodedChallenge<C: CurveAffine> {
    inner: C::ScalarExt,
}

impl<C: CurveAffine> EncodedChallenge<C> for PoseidonEncodedChallenge<C> {
    type Input = C::ScalarExt;

    fn new(challenge_input: &Self::Input) -> Self {
        Self {
            inner: *challenge_input,
        }
    }

    fn get_scalar(&self) -> <C>::Scalar {
        self.inner
    }
}

pub struct PoseidonRead<R: io::Read, C: CurveAffine, E: EncodedChallenge<C>> {
    poseidon: PoseidonPure<C>,
    reader: R,
    _mark: PhantomData<E>,
}

impl<R: io::Read, C: CurveAffine, E: EncodedChallenge<C>> PoseidonRead<R, C, E> {
    pub fn init(reader: R) -> Self {
        Self {
            poseidon: PoseidonPure::default(),
            reader,
            _mark: PhantomData,
        }
    }
    pub fn init_with_poseidon(reader: R, mut poseidon: PoseidonPure<C>) -> Self {
        poseidon.reset();
        Self {
            poseidon,
            reader,
            _mark: PhantomData,
        }
    }

    pub fn get_poseidon_spec(&self) -> std::sync::Arc<poseidon::Spec<C::ScalarExt, T, RATE>> {
        self.poseidon.get_spec()
    }
}

impl<R: io::Read, C: CurveAffine> Transcript<C, PoseidonEncodedChallenge<C>>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn squeeze_challenge(&mut self) -> PoseidonEncodedChallenge<C> {
        self.poseidon.squeeze_challenge()
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.poseidon.common_point(point)
    }

    fn common_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        self.poseidon.common_scalar(scalar)
    }
}

fn read_curve_point<R: io::Read, C: CurveAffine>(reader: &mut R) -> io::Result<C> {
    let mut compressed = C::Repr::default();
    reader.read_exact(compressed.as_mut())?;
    let point: C = Option::from(C::from_bytes(&compressed))
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid point encoding in proof"))?;
    Ok(point)
}

fn read_curve_scalar<R: io::Read, C: CurveAffine>(reader: &mut R) -> io::Result<<C>::Scalar> {
    let mut data = <C::Scalar as PrimeField>::Repr::default();
    reader.read_exact(data.as_mut())?;
    let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "invalid field element encoding in proof",
        )
    })?;
    Ok(scalar)
}

impl<R: io::Read, C: CurveAffine> TranscriptRead<C, PoseidonEncodedChallenge<C>>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn read_point(&mut self) -> io::Result<C> {
        let point = read_curve_point::<R, C>(&mut self.reader)?;
        self.common_point(point)?;

        Ok(point)
    }

    fn read_scalar(&mut self) -> io::Result<<C>::Scalar> {
        let scalar = read_curve_scalar::<R, C>(&mut self.reader)?;
        self.common_scalar(scalar)?;

        Ok(scalar)
    }
}

pub struct PoseidonWrite<W: io::Write, C: CurveAffine, E: EncodedChallenge<C>> {
    poseidon: PoseidonPure<C>,
    writer: W,
    _mark: PhantomData<E>,
}

impl<W: io::Write, C: CurveAffine, E: EncodedChallenge<C>> PoseidonWrite<W, C, E> {
    pub fn init(writer: W) -> Self {
        Self {
            poseidon: PoseidonPure::default(),
            writer,
            _mark: PhantomData,
        }
    }

    pub fn init_with_poseidon(writer: W, mut poseidon: PoseidonPure<C>) -> Self {
        poseidon.reset();
        Self {
            poseidon,
            writer,
            _mark: PhantomData,
        }
    }

    pub fn finalize(self) -> W {
        self.writer
    }
}

impl<W: io::Write, C: CurveAffine> Transcript<C, PoseidonEncodedChallenge<C>>
    for PoseidonWrite<W, C, PoseidonEncodedChallenge<C>>
{
    fn squeeze_challenge(&mut self) -> PoseidonEncodedChallenge<C> {
        self.poseidon.squeeze_challenge()
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.poseidon.common_point(point)
    }

    fn common_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        self.poseidon.common_scalar(scalar)
    }
}

impl<W: io::Write, C: CurveAffine> TranscriptWrite<C, PoseidonEncodedChallenge<C>>
    for PoseidonWrite<W, C, PoseidonEncodedChallenge<C>>
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        //assert!(point != C::identity());
        self.common_point(point)?;
        let compressed = point.to_bytes();
        self.writer.write_all(compressed.as_ref())
    }

    fn write_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        self.common_scalar(scalar)?;
        let data = scalar.to_repr();
        self.writer.write_all(data.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct PoseidonPure<C: CurveAffine> {
    state: Poseidon<C::ScalarExt, T, RATE>,
}

impl<C: CurveAffine> Default for PoseidonPure<C> {
    fn default() -> Self {
        Self {
            state: Poseidon::new(R_F, R_P),
        }
    }
}

impl<C: CurveAffine> PoseidonPure<C> {
    pub fn reset(&mut self) {
        self.state.reset()
    }
    pub fn get_spec(&self) -> std::sync::Arc<poseidon::Spec<C::ScalarExt, T, RATE>> {
        self.state.get_spec()
    }
}

impl<C: CurveAffine> Transcript<C, PoseidonEncodedChallenge<C>> for PoseidonPure<C> {
    fn squeeze_challenge(&mut self) -> PoseidonEncodedChallenge<C> {
        self.state.update(&[C::ScalarExt::from(PREFIX_CHALLENGE)]);
        PoseidonEncodedChallenge::new(&self.state.squeeze())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[C::ScalarExt::from(PREFIX_POINT)]);

        let elem = encode_point(&point);

        self.state.update(&elem);
        Ok(())
    }

    fn common_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        self.state.update(&[C::ScalarExt::from(PREFIX_SCALAR)]);
        self.state.update(&[scalar]);

        Ok(())
    }
}

impl<R: io::Read, C: CurveAffine> FieldTranscript<C::Scalar>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn squeeze_challenge(&mut self) -> C::Scalar {
        self.poseidon.squeeze_challenge().get_scalar()
    }

    fn common_field_element(&mut self, scalar: &C::Scalar) -> Result<(), HyperError> {
        self.poseidon
            .common_scalar(*scalar)
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))
    }
}

impl<R: io::Read, C: CurveAffine> FieldTranscriptRead<C::Scalar>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn read_field_element(&mut self) -> Result<<C>::Scalar, HyperError> {
        let scalar = read_curve_scalar::<R, C>(&mut self.reader)
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))?;
        self.common_field_element(&scalar)?;

        Ok(scalar)
    }
}

impl<R: io::Read, C: CurveAffine> PointTranscript<C, C::Scalar>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn common_commitment(&mut self, point: &C) -> Result<(), HyperError> {
        self.poseidon
            .common_point(*point)
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))
    }
}

impl<R: io::Read, C: CurveAffine> PointTranscriptRead<C, C::Scalar>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn read_commitment(&mut self) -> Result<C, HyperError> {
        let point = read_curve_point(&mut self.reader)
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))?;
        self.common_commitment(&point)?;

        Ok(point)
    }
}

impl<W: io::Write, C: CurveAffine> FieldTranscript<C::Scalar>
    for PoseidonWrite<W, C, PoseidonEncodedChallenge<C>>
{
    fn squeeze_challenge(&mut self) -> C::Scalar {
        self.poseidon.squeeze_challenge().get_scalar()
    }

    fn common_field_element(&mut self, scalar: &C::Scalar) -> Result<(), HyperError> {
        self.poseidon
            .common_scalar(*scalar)
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))
    }
}

impl<W: io::Write, C: CurveAffine> FieldTranscriptWrite<C::Scalar>
    for PoseidonWrite<W, C, PoseidonEncodedChallenge<C>>
{
    fn write_field_element(&mut self, scalar: &<C>::Scalar) -> Result<(), HyperError> {
        self.common_field_element(scalar)?;
        let data = scalar.to_repr();
        self.writer
            .write_all(data.as_ref())
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))
    }
}

impl<W: io::Write, C: CurveAffine> PointTranscript<C, C::Scalar>
    for PoseidonWrite<W, C, PoseidonEncodedChallenge<C>>
{
    fn common_commitment(&mut self, point: &C) -> Result<(), HyperError> {
        self.poseidon
            .common_point(*point)
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))
    }
}

impl<W: io::Write, C: CurveAffine> PointTranscriptWrite<C, C::Scalar>
    for PoseidonWrite<W, C, PoseidonEncodedChallenge<C>>
{
    fn write_commitment(&mut self, point: &C) -> Result<(), HyperError> {
        //assert!(point != C::identity());
        self.common_commitment(point)?;
        let compressed = point.to_bytes();
        self.writer
            .write_all(compressed.as_ref())
            .map_err(|err| HyperError::Transcript(err.kind(), err.to_string()))
    }
}
