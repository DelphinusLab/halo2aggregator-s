use halo2_proofs::arithmetic::*;
use halo2_proofs::pairing::bn256::*;

pub trait G2AffineBaseHelper: MultiMillerLoop {
    fn decode(
        b: <Self::G2Affine as CurveAffine>::Base,
    ) -> (
        <Self::G1Affine as CurveAffine>::Base,
        <Self::G1Affine as CurveAffine>::Base,
    );
}

impl G2AffineBaseHelper for Bn256 {
    fn decode(b: Fq2) -> (Fq, Fq) {
        (b.c0, b.c1)
    }
}

pub trait GtHelper: MultiMillerLoop {
    fn decode_gt(
        b: Self::Gt,
    ) -> (
        (
            (
                <Self::G1Affine as CurveAffine>::Base,
                <Self::G1Affine as CurveAffine>::Base,
            ),
            (
                <Self::G1Affine as CurveAffine>::Base,
                <Self::G1Affine as CurveAffine>::Base,
            ),
            (
                <Self::G1Affine as CurveAffine>::Base,
                <Self::G1Affine as CurveAffine>::Base,
            ),
        ),
        (
            (
                <Self::G1Affine as CurveAffine>::Base,
                <Self::G1Affine as CurveAffine>::Base,
            ),
            (
                <Self::G1Affine as CurveAffine>::Base,
                <Self::G1Affine as CurveAffine>::Base,
            ),
            (
                <Self::G1Affine as CurveAffine>::Base,
                <Self::G1Affine as CurveAffine>::Base,
            ),
        ),
    );
}

impl GtHelper for Bn256 {
    fn decode_gt(
        a: Self::Gt,
    ) -> (
        ((Fq, Fq), (Fq, Fq), (Fq, Fq)),
        ((Fq, Fq), (Fq, Fq), (Fq, Fq)),
    ) {
        (
            (
                (a.0.c0.c0.c0, a.0.c0.c0.c1),
                (a.0.c0.c1.c0, a.0.c0.c1.c1),
                (a.0.c0.c2.c0, a.0.c0.c2.c1),
            ),
            (
                (a.0.c1.c0.c0, a.0.c1.c0.c1),
                (a.0.c1.c1.c0, a.0.c1.c1.c1),
                (a.0.c1.c2.c0, a.0.c1.c2.c1),
            ),
        )
    }
}
