pub mod field;
pub mod ecc;

pub trait ArithCommonChip {
    type Value: Clone;
    type AssignedValue: Clone;

    fn add(&mut self, a: &Self::AssignedValue, b: &Self::AssignedValue) -> Self::AssignedValue;

    fn sub(&mut self, a: &Self::AssignedValue, b: &Self::AssignedValue) -> Self::AssignedValue;

    fn assign_const(&mut self, c: &Self::Value) -> &Self::AssignedValue;

    fn assign_var(&mut self, v: &Self::Value) -> &Self::AssignedValue;

    fn get_value(&mut self, v: &Self::AssignedValue) -> &Self::Value;

    fn normalize(&mut self, v: &Self::AssignedValue) -> &Self::AssignedValue;
}
