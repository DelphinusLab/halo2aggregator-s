use super::{field::ArithFieldChip, ArithCommonChip};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use std::fmt::Debug;

pub trait ArithEccChip:
    ArithCommonChip<Value = Self::Point, AssignedValue = Self::AssignedPoint>
{
    type Point: CurveAffine;
    type AssignedPoint: Clone + Debug;
    type Scalar: FieldExt;
    type AssignedScalar: Clone + Debug;
    type Native: FieldExt;
    type AssignedNative: Clone + Debug;

    type ScalarChip: ArithFieldChip<Field = Self::Scalar, AssignedField = Self::AssignedScalar>;
    type NativeChip: ArithFieldChip<Field = Self::Native, AssignedField = Self::AssignedNative>;

    fn scalar_mul(
        &mut self,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Self::AssignedPoint;

    fn msm(
        &self,
        points: Vec<Self::AssignedPoint>,
        scalars: Vec<Self::AssignedScalar>,
    ) -> Self::AssignedPoint;
}
