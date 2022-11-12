use super::lookup;
use super::permutation;
use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Expression;
use std::rc::Rc;

pub struct PlonkCommonSetup {
    pub l: u32,
    pub n: u32,
}

pub struct VerifierParams<C: CurveAffine> {
    pub key: String,
    pub gates: Vec<Expression<Rc<AstScalar<C>>>>,
    pub common: PlonkCommonSetup,

    pub(crate) lookup_evaluated: Vec<Vec<lookup::Evaluated<C>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<C>>,

    pub instance_commitments: Vec<Rc<AstPoint<C>>>,
    pub instance_evals: Vec<Rc<AstScalar<C>>>,
    pub instance_queries: Vec<(usize, i32)>,

    pub advice_commitments: Vec<Rc<AstPoint<C>>>,
    pub advice_evals: Vec<Vec<Rc<AstScalar<C>>>>,
    pub advice_queries: Vec<(usize, i32)>,

    pub fixed_commitments: Vec<Rc<AstPoint<C>>>,
    pub fixed_evals: Vec<Rc<AstScalar<C>>>,
    pub fixed_queries: Vec<(usize, i32)>,

    pub permutation_commitments: Vec<Rc<AstPoint<C>>>,
    pub permutation_evals: Vec<Rc<AstScalar<C>>>,

    pub vanish_commitments: Vec<Rc<AstPoint<C>>>,
    pub random_commitment: Rc<AstPoint<C>>,

    pub w: Vec<Rc<AstPoint<C>>>,

    pub random_eval: Rc<AstScalar<C>>,
    pub beta: Rc<AstScalar<C>>,
    pub gamma: Rc<AstScalar<C>>,
    pub theta: Rc<AstScalar<C>>,
    pub delta: Rc<AstScalar<C>>,

    pub x: Rc<AstScalar<C>>,
    pub x_next: Rc<AstScalar<C>>,
    pub x_last: Rc<AstScalar<C>>,
    pub x_inv: Rc<AstScalar<C>>,
    pub xn: Rc<AstScalar<C>>,

    pub y: Rc<AstScalar<C>>,
    pub u: Rc<AstScalar<C>>,
    pub v: Rc<AstScalar<C>>,
    pub omega: Rc<AstScalar<C>>,
}
