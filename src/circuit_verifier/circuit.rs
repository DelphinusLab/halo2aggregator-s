use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::circuit::floor_planner::FlatFloorPlanner;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Instance;
use halo2ecc_s::assign::AssignedValue;
use halo2ecc_s::circuit::base_chip::BaseChip;
use halo2ecc_s::circuit::base_chip::BaseChipConfig;
use halo2ecc_s::circuit::range_chip::RangeChip;
use halo2ecc_s::circuit::range_chip::RangeChipConfig;
use halo2ecc_s::circuit::select_chip::SelectChip;
use halo2ecc_s::circuit::select_chip::SelectChipConfig;
use halo2ecc_s::context::Records;
use std::rc::Rc;

pub struct AggregatorCircuitOption<C: CurveAffine> {
    pub circuit_with_select_chip: Option<AggregatorCircuit<C>>,
    pub circuit_without_select_chip: Option<AggregatorNoSelectCircuit<C>>,
}

impl<C: CurveAffine> From<AggregatorCircuit<C>> for AggregatorCircuitOption<C> {
    fn from(circuit_with_select_chip: AggregatorCircuit<C>) -> Self {
        Self {
            circuit_with_select_chip: Some(circuit_with_select_chip),
            circuit_without_select_chip: None,
        }
    }
}

impl<C: CurveAffine> From<AggregatorNoSelectCircuit<C>> for AggregatorCircuitOption<C> {
    fn from(circuit_without_select_chip: AggregatorNoSelectCircuit<C>) -> Self {
        Self {
            circuit_with_select_chip: None,
            circuit_without_select_chip: Some(circuit_without_select_chip),
        }
    }
}

#[derive(Clone)]
pub struct AggregatorChipConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
    select_chip_config: SelectChipConfig,
    instance_col: Column<Instance>,
}

#[derive(Clone)]
pub struct AggregatorCircuit<C: CurveAffine> {
    pub records: Rc<Records<C::Scalar>>,
    instances: Vec<AssignedValue<C::Scalar>>,
}

impl<C: CurveAffine> AggregatorCircuit<C> {
    pub fn new(records: Rc<Records<C::Scalar>>, instances: Vec<AssignedValue<C::Scalar>>) -> Self {
        Self { records, instances }
    }
}

impl<C: CurveAffine> Circuit<C::Scalar> for AggregatorCircuit<C> {
    type Config = AggregatorChipConfig;
    type FloorPlanner = FlatFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<C::Scalar>::configure(meta);
        let select_chip_config = SelectChip::<C::Scalar>::configure(meta);
        let instance_col = meta.instance_column();
        meta.enable_equality(instance_col);
        AggregatorChipConfig {
            base_chip_config,
            range_chip_config,
            select_chip_config,
            instance_col,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Scalar>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "synthesize");

        let base_chip = BaseChip::new(config.base_chip_config);
        let range_chip = RangeChip::<C::Scalar>::new(config.range_chip_config);
        let select_chip = SelectChip::new(config.select_chip_config);

        let instance_cells = layouter.assign_region(
            || "base",
            |mut region| {
                let timer = start_timer!(|| "assign");
                let cells =
                    self.records
                        .assign_all(&mut region, &base_chip, &range_chip, &select_chip)?;

                let r = Some(
                    self.instances
                        .iter()
                        .map(|instance| {
                            cells[instance.cell.region as usize][instance.cell.col]
                                [instance.cell.row]
                                .as_ref()
                                .unwrap()
                                .cell()
                                .clone()
                        })
                        .collect::<Vec<_>>(),
                );
                end_timer!(timer);

                Ok(r)
            },
        )?;

        match instance_cells {
            Some(instance_cells) => {
                range_chip.init_table(&mut layouter)?;

                for (i, cell) in instance_cells.into_iter().enumerate() {
                    layouter.constrain_instance(cell, config.instance_col, i)?;
                }
            }
            // skip on row check synthesize
            None => {}
        };

        end_timer!(timer);

        Ok(())
    }
}

// Without Select Chip
#[derive(Clone)]
pub struct AggregatorNoSelectChipConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
    instance_col: Column<Instance>,
}

#[derive(Clone)]
pub struct AggregatorNoSelectCircuit<C: CurveAffine> {
    pub records: Rc<Records<C::Scalar>>,
    instances: Vec<AssignedValue<C::Scalar>>,
}

impl<C: CurveAffine> AggregatorNoSelectCircuit<C> {
    pub fn new(records: Rc<Records<C::Scalar>>, instances: Vec<AssignedValue<C::Scalar>>) -> Self {
        Self { records, instances }
    }
}

impl<C: CurveAffine> Circuit<C::Scalar> for AggregatorNoSelectCircuit<C> {
    type Config = AggregatorNoSelectChipConfig;
    type FloorPlanner = FlatFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<C::Scalar>::configure(meta);
        let instance_col = meta.instance_column();
        meta.enable_equality(instance_col);
        AggregatorNoSelectChipConfig {
            base_chip_config,
            range_chip_config,
            instance_col,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Scalar>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "synthesize");

        let base_chip = BaseChip::new(config.base_chip_config);
        let range_chip = RangeChip::<C::Scalar>::new(config.range_chip_config);

        let instance_cells = layouter.assign_region(
            || "base",
            |mut region| {
                let timer = start_timer!(|| "assign");
                let cells = self.records.assign_all_with_optional_select_chip(
                    &mut region,
                    &base_chip,
                    &range_chip,
                    None,
                )?;

                let r = Some(
                    self.instances
                        .iter()
                        .map(|instance| {
                            cells[instance.cell.region as usize][instance.cell.col]
                                [instance.cell.row]
                                .as_ref()
                                .unwrap()
                                .cell()
                                .clone()
                        })
                        .collect::<Vec<_>>(),
                );
                end_timer!(timer);

                Ok(r)
            },
        )?;

        match instance_cells {
            Some(instance_cells) => {
                range_chip.init_table(&mut layouter)?;

                for (i, cell) in instance_cells.into_iter().enumerate() {
                    layouter.constrain_instance(cell, config.instance_col, i)?;
                }
            }
            // skip on row check synthesize
            None => {}
        };

        end_timer!(timer);

        Ok(())
    }
}
