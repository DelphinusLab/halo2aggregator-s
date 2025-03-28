use crate::transcript::poseidon::PoseidonEncodedChallenge;
use crate::transcript::poseidon::PoseidonRead;
use crate::transcript::poseidon::PREFIX_CHALLENGE;
use crate::transcript::poseidon::PREFIX_POINT;
use crate::transcript::poseidon::PREFIX_SCALAR;
use crate::transcript::poseidon::RATE;
use crate::transcript::poseidon::R_F;
use crate::transcript::poseidon::T;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::transcript::TranscriptRead;
use halo2ecc_o::assign::*;
use halo2ecc_o::chips::ecc_chip::EccChipBaseOps;
use halo2ecc_o::chips::native_chip::NativeChipOps;
use halo2ecc_o::context::NativeScalarEccContext;
use halo2ecc_o::context::PlonkRegionContext;
use poseidon::SparseMDSMatrix;
use poseidon::Spec;
use std::io;
use std::sync::Arc;

pub struct PoseidonChipRead<R: io::Read, C: CurveAffine> {
    read: PoseidonRead<R, C, PoseidonEncodedChallenge<C>>,
    state: PoseidonChipContext<C::ScalarExt>,
    prefix: Vec<AssignedValue<C::ScalarExt>>,
}

impl<R: io::Read, C: CurveAffine> PoseidonChipRead<R, C> {
    pub fn init(
        read: PoseidonRead<R, C, PoseidonEncodedChallenge<C>>,
        circuit: &mut NativeScalarEccContext<C>,
    ) -> Self {
        let state = PoseidonChipContext::new(
            &mut circuit.integer_context().plonk_region_context(),
            read.get_poseidon_spec(),
        );
        let plonk_region_context = &mut circuit.integer_context().plonk_region_context();
        Self {
            read,
            state,
            prefix: vec![
                plonk_region_context
                    .assign_constant(C::ScalarExt::from(PREFIX_CHALLENGE))
                    .unwrap(),
                plonk_region_context
                    .assign_constant(C::ScalarExt::from(PREFIX_POINT))
                    .unwrap(),
                plonk_region_context
                    .assign_constant(C::ScalarExt::from(PREFIX_SCALAR))
                    .unwrap(),
            ],
        }
    }

    pub fn read_scalar(
        &mut self,
        circuit: &mut NativeScalarEccContext<C>,
    ) -> AssignedValue<C::ScalarExt> {
        let s = self.read.read_scalar().unwrap();
        let s = circuit
            .integer_context()
            .plonk_region_context()
            .assign(s)
            .unwrap();
        self.common_scalar(circuit, &s);
        s
    }

    pub fn read_point(
        &mut self,
        circuit: &mut NativeScalarEccContext<C>,
    ) -> AssignedPoint<C, C::ScalarExt> {
        let p = self.read.read_point().unwrap();
        let p = circuit.assign_point(Some(p)).unwrap();
        let p = circuit.ecc_reduce(&p).unwrap();
        self.common_point(circuit, &p);
        p
    }

    pub fn common_scalar(
        &mut self,
        circuit: &mut NativeScalarEccContext<C>,
        s: &AssignedValue<C::ScalarExt>,
    ) {
        self.state.update(
            &mut circuit.integer_context().plonk_region_context(),
            vec![self.prefix[2], s.clone()],
        );
    }

    pub fn common_point(
        &mut self,
        circuit: &mut NativeScalarEccContext<C>,
        p: &AssignedPoint<C, C::ScalarExt>,
    ) {
        self.state.update(
            &mut circuit.integer_context().plonk_region_context(),
            vec![self.prefix[1]],
        );
        let sl = circuit.ecc_encode(p).unwrap();
        self.state
            .update(&mut circuit.integer_context().plonk_region_context(), sl);
    }

    pub fn squeeze(
        &mut self,
        circuit: &mut NativeScalarEccContext<C>,
    ) -> AssignedValue<C::ScalarExt> {
        self.state.update(
            &mut circuit.integer_context().plonk_region_context(),
            vec![self.prefix[0]],
        );
        self.state
            .squeeze(&mut circuit.integer_context().plonk_region_context())
    }
}

struct PoseidonChipState<F: FieldExt>([AssignedValue<F>; T]);

pub struct PoseidonChipContext<F: FieldExt> {
    spec: Arc<Spec<F, T, RATE>>,
    state: PoseidonChipState<F>,
    absorbing: Vec<AssignedValue<F>>,
}

impl<F: FieldExt> PoseidonChipContext<F> {
    pub fn new(chip: &mut PlonkRegionContext<'_, F>, spec: Arc<Spec<F, T, RATE>>) -> Self {
        let zero = chip.assign_constant(F::zero()).unwrap();
        let mut state = [zero; T];
        state[0] = chip.assign_constant(F::from_u128(1u128 << 64)).unwrap();
        Self {
            spec,
            state: PoseidonChipState(state),
            absorbing: vec![],
        }
    }

    pub fn update(
        &mut self,
        chip: &mut PlonkRegionContext<'_, F>,
        mut inputs: Vec<AssignedValue<F>>,
    ) {
        self.absorbing.append(&mut inputs);

        if self.absorbing.len() < RATE {
            return;
        }

        let mut values = vec![];
        values.append(&mut self.absorbing);

        for chunk in values.chunks(RATE) {
            if chunk.len() < RATE {
                self.absorbing = chunk.to_vec();
            } else {
                self.permute(chip, &chunk, false);
            }
        }
    }

    pub fn squeeze(&mut self, chip: &mut PlonkRegionContext<'_, F>) -> AssignedValue<F> {
        assert!(self.absorbing.len() < RATE);

        let mut values = vec![];
        values.append(&mut self.absorbing);

        self.permute(chip, &values, true);

        self.state.0[1]
    }

    fn permute(
        &mut self,
        chip: &mut PlonkRegionContext<'_, F>,
        inputs: &[AssignedValue<F>],
        on_squeeze: bool,
    ) {
        let r_f = R_F / 2;
        let mds = &self.spec.mds_matrices().mds().rows();

        let constants = &self.spec.constants().start();
        self.state
            .absorb_with_pre_constants(chip, inputs, &constants[0], on_squeeze);

        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.state.sbox_full(chip, constants);
            self.state.apply_mds(chip, mds);
        }

        let pre_sparse_mds = &self.spec.mds_matrices().pre_sparse_mds().rows();
        self.state.sbox_full(chip, constants.last().unwrap());
        self.state.apply_mds(chip, &pre_sparse_mds);

        let sparse_matrices = &self.spec.mds_matrices().sparse_matrices();
        let constants = &self.spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.state.sbox_part(chip, constant);
            self.state.apply_sparse_mds(chip, sparse_mds);
        }

        let constants = &self.spec.constants().end();
        for constants in constants.iter() {
            self.state.sbox_full(chip, constants);
            self.state.apply_mds(chip, mds);
        }
        self.state.sbox_full(chip, &[F::zero(); T]);
        self.state.apply_mds(chip, mds);
    }
}

impl<F: FieldExt> PoseidonChipState<F> {
    fn x_power5_with_constant(
        chip: &mut PlonkRegionContext<'_, F>,
        x: &AssignedValue<F>,
        constant: F,
    ) -> AssignedValue<F> {
        let x2 = chip.mul(x, x).unwrap();
        let x4 = chip.mul(&x2, &x2).unwrap();
        chip.mul_add_constant(&x, &x4, Some(constant)).unwrap()
    }

    fn sbox_full(&mut self, chip: &mut PlonkRegionContext<'_, F>, constants: &[F; T]) {
        for (x, constant) in self.0.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(chip, x, *constant);
        }
    }

    fn sbox_part(&mut self, chip: &mut PlonkRegionContext<'_, F>, constant: &F) {
        self.0[0] = Self::x_power5_with_constant(chip, &self.0[0], constant.clone());
    }

    fn absorb_with_pre_constants(
        &mut self,
        chip: &mut PlonkRegionContext<'_, F>,
        inputs: &[AssignedValue<F>],
        pre_constants: &[F; T],
        on_squeeze: bool,
    ) {
        assert!(inputs.len() < T);
        let zero = F::zero();
        let one = F::one();

        let offset = inputs.len() + 1;

        self.0[0] = chip.add_constant(&self.0[0], pre_constants[0]).unwrap();

        for ((x, constant), input) in self
            .0
            .iter_mut()
            .skip(1)
            .zip(pre_constants.iter().skip(1))
            .zip(inputs.iter())
        {
            *x = chip
                .sum_with_constant(&[(&x, one), (input, one)], Some(*constant))
                .unwrap();
        }

        for (i, (x, constant)) in self
            .0
            .iter_mut()
            .skip(offset)
            .zip(pre_constants.iter().skip(offset))
            .enumerate()
        {
            *x = chip
                .add_constant(x, *constant + if i == 0 && on_squeeze { one } else { zero })
                .unwrap();
        }
    }

    fn apply_mds(&mut self, chip: &mut PlonkRegionContext<'_, F>, mds: &[[F; T]; T]) {
        let res = mds
            .iter()
            .map(|row| {
                let a = self
                    .0
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| (e, *word))
                    .collect::<Vec<_>>();

                chip.sum_with_constant(&a, None).unwrap()
            })
            .collect::<Vec<_>>();

        self.0 = res.try_into().unwrap();
    }

    fn apply_sparse_mds(
        &mut self,
        chip: &mut PlonkRegionContext<'_, F>,
        mds: &SparseMDSMatrix<F, T, RATE>,
    ) {
        let a = self
            .0
            .iter()
            .zip(mds.row().iter())
            .map(|(e, word)| (e, *word))
            .collect::<Vec<_>>();

        let mut res = vec![chip.sum_with_constant(&a, None).unwrap()];

        for (e, x) in mds.col_hat().iter().zip(self.0.iter().skip(1)) {
            res.push(
                chip.sum_with_constant(&[(&self.0[0], *e), (&x, F::one())], None)
                    .unwrap(),
            );
        }

        for (x, new_x) in self.0.iter_mut().zip(res.into_iter()) {
            *x = new_x
        }
    }
}
