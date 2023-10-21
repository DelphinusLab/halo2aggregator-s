use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::Transcript;
use halo2_proofs::transcript::TranscriptRead;
use halo2_proofs::transcript::TranscriptWrite;
use halo2ecc_s::circuit::range_chip::MAX_BITS;
use halo2ecc_s::circuit::range_chip::RANGE_VALUE_DECOMPOSE;
use halo2ecc_s::utils::bn_to_field;
use halo2ecc_s::utils::field_to_bn;
use num_bigint::BigUint;
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
    state: Poseidon<C::ScalarExt, T, RATE>,
    reader: R,
    _mark: PhantomData<E>,
}

impl<R: io::Read, C: CurveAffine, E: EncodedChallenge<C>> PoseidonRead<R, C, E> {
    pub fn init(reader: R) -> Self {
        Self {
            state: Poseidon::new(R_F, R_P),
            reader,
            _mark: PhantomData,
        }
    }
}

impl<R: io::Read, C: CurveAffine> Transcript<C, PoseidonEncodedChallenge<C>>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn squeeze_challenge(&mut self) -> PoseidonEncodedChallenge<C> {
        self.state.update(&[C::ScalarExt::from(PREFIX_CHALLENGE)]);
        PoseidonEncodedChallenge::new(&self.state.squeeze())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[C::ScalarExt::from(PREFIX_POINT)]);
        let x_y: Option<_> = point.coordinates().map(|c| (*c.x(), *c.y())).into();
        let (x, y) = x_y.unwrap_or((C::Base::zero(), C::Base::zero()));
        let x_bn = field_to_bn(&x);
        let y_bn = field_to_bn(&y);

        let bits = RANGE_VALUE_DECOMPOSE * MAX_BITS;
        let chunk_bits = bits * 2;

        let chunk0 = &x_bn & ((BigUint::from(1u64) << chunk_bits) - 1u64);
        let chunk1 =
            (x_bn >> chunk_bits) + ((&y_bn & ((BigUint::from(1u64) << bits) - 1u64)) << bits);
        let chunk2 = y_bn >> bits;

        self.state.update(
            &[chunk0, chunk1, chunk2]
                .iter()
                .map(|x| bn_to_field(&x))
                .collect::<Vec<_>>(),
        );

        Ok(())
    }

    fn common_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        self.state.update(&[C::ScalarExt::from(PREFIX_SCALAR)]);
        self.state.update(&[scalar]);

        Ok(())
    }
}

impl<R: io::Read, C: CurveAffine> TranscriptRead<C, PoseidonEncodedChallenge<C>>
    for PoseidonRead<R, C, PoseidonEncodedChallenge<C>>
{
    fn read_point(&mut self) -> io::Result<C> {
        let mut compressed = C::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "invalid point encoding in proof")
        })?;
        self.common_point(point)?;

        Ok(point)
    }

    fn read_scalar(&mut self) -> io::Result<<C>::Scalar> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "invalid field element encoding in proof",
            )
        })?;
        self.common_scalar(scalar)?;

        Ok(scalar)
    }
}

pub struct PoseidonWrite<W: io::Write, C: CurveAffine, E: EncodedChallenge<C>> {
    state: Poseidon<C::ScalarExt, T, RATE>,
    writer: W,
    _mark: PhantomData<E>,
}

impl<W: io::Write, C: CurveAffine, E: EncodedChallenge<C>> PoseidonWrite<W, C, E> {
    pub fn init(writer: W) -> Self {
        Self {
            state: Poseidon::new(R_F, R_P),
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
        self.state.update(&[C::ScalarExt::from(PREFIX_CHALLENGE)]);
        PoseidonEncodedChallenge::new(&self.state.squeeze())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[C::ScalarExt::from(PREFIX_POINT)]);
        let x_y: Option<_> = point.coordinates().map(|c| (*c.x(), *c.y())).into();
        let (x, y) = x_y.unwrap_or((C::Base::zero(), C::Base::zero()));
        let x_bn = field_to_bn(&x);
        let y_bn = field_to_bn(&y);

        let bits = RANGE_VALUE_DECOMPOSE * MAX_BITS;
        let chunk_bits = bits * 2;

        let chunk0 = &x_bn & ((BigUint::from(1u64) << chunk_bits) - 1u64);
        let chunk1 =
            (x_bn >> chunk_bits) + ((&y_bn & ((BigUint::from(1u64) << bits) - 1u64)) << bits);
        let chunk2 = y_bn >> bits;

        self.state.update(
            &[chunk0, chunk1, chunk2]
                .iter()
                .map(|x| bn_to_field(&x))
                .collect::<Vec<_>>(),
        );

        Ok(())
    }

    fn common_scalar(&mut self, scalar: <C>::Scalar) -> io::Result<()> {
        self.state.update(&[C::ScalarExt::from(PREFIX_SCALAR)]);
        self.state.update(&[scalar]);

        Ok(())
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
