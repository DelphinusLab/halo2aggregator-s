use super::ArithCommonChip;
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

pub trait ArithFieldChip:
    ArithCommonChip<Value = Self::Field, AssignedValue = Self::AssignedField>
{
    type Field: FieldExt;
    type AssignedField: Clone + Debug;

    fn mul(
        &mut self,
        a: &mut Self::AssignedField,
        b: &mut Self::AssignedField,
    ) -> Self::AssignedField;

    fn div(
        &mut self,
        a: &mut Self::AssignedField,
        b: &mut Self::AssignedField,
    ) -> Self::AssignedField;
}
