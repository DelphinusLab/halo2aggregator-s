use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::circuit::floor_planner::V1;
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

#[derive(Clone)]
pub struct AggregatorChipConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
    select_chip_config: SelectChipConfig,
    instance_col: Column<Instance>,
}

#[derive(Clone)]
pub struct AggregatorCircuit<C: CurveAffine> {
    pub records: Rc<Records<C::ScalarExt>>,
    instances: Vec<AssignedValue<C::ScalarExt>>,
}

impl<C: CurveAffine> AggregatorCircuit<C> {
    pub fn new(
        records: Rc<Records<C::ScalarExt>>,
        instances: Vec<AssignedValue<C::ScalarExt>>,
    ) -> Self {
        Self { records, instances }
    }
}

impl<C: CurveAffine> Circuit<C::ScalarExt> for AggregatorCircuit<C> {
    type Config = AggregatorChipConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let select_chip_config = SelectChip::configure(meta);
        let range_chip_config = RangeChip::<C::ScalarExt>::configure(meta);
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
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "synthesize");

        let base_chip = BaseChip::new(config.base_chip_config);
        let select_chip = SelectChip::new(config.select_chip_config);
        let range_chip = RangeChip::<C::ScalarExt>::new(config.range_chip_config);

        let mut instance_cells = None;

        layouter.assign_region(
            || "base",
            |mut region| {
                let timer = start_timer!(|| "assign");
                let cells = self.records.assign_all_opt(
                    &mut region,
                    &base_chip,
                    &range_chip,
                    &select_chip,
                )?;

                match cells {
                    Some(cells) => {
                        instance_cells = Some(
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
                        )
                    }
                    None => {}
                }
                end_timer!(timer);
                Ok(())
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
