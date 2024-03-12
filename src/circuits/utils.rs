use crate::circuit_verifier::build_aggregate_verify_circuit;
use crate::circuit_verifier::circuit::AggregatorCircuit;
use crate::circuit_verifier::circuit::AggregatorCircuitOption;
use crate::circuit_verifier::G2AffineBaseHelper;
use crate::native_verifier::verify_proofs;
use crate::transcript::poseidon::PoseidonPure;
use crate::transcript::poseidon::PoseidonRead;
use crate::transcript::poseidon::PoseidonWrite;
use crate::transcript::sha256::ShaRead;
use crate::transcript::sha256::ShaWrite;
use ark_std::end_timer;
use ark_std::rand::rngs::OsRng;
use ark_std::start_timer;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::plonk::create_proof_ext;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::verify_proof_ext;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Blake2bWrite;
use halo2_proofs::transcript::Transcript;
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::NativeScalarEccContext;
use std::io::Read;
use std::io::Write;
use std::path::Path;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TranscriptHash {
    Blake2b,
    Poseidon,
    Sha,
    Keccak,
}

pub fn load_or_build_unsafe_params<E: MultiMillerLoop>(
    k: u32,
    cache_file_opt: Option<&Path>,
) -> Params<E::G1Affine> {
    if let Some(cache_file) = &cache_file_opt {
        if Path::exists(&cache_file) {
            println!("read params K={} from {:?}", k, cache_file);
            let mut fd = std::fs::File::open(&cache_file).unwrap();
            return Params::<E::G1Affine>::read(&mut fd).unwrap();
        }
    }

    let params = Params::<E::G1Affine>::unsafe_setup::<E>(k);

    if let Some(cache_file) = &cache_file_opt {
        println!("write params K={} to {:?}", k, cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        params.write(&mut fd).unwrap();
    };

    params
}

pub fn load_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    cache_file: &Path,
) -> VerifyingKey<E::G1Affine> {
    println!("read vkey from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    VerifyingKey::read::<_, C>(&mut fd, params).unwrap()
}

pub fn load_or_build_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    circuit: &C,
    cache_file_opt: Option<&Path>,
) -> VerifyingKey<E::G1Affine> {
    if let Some(cache_file) = &cache_file_opt {
        if Path::exists(&cache_file) {
            return load_vkey::<E, C>(params, &cache_file);
        }
    }

    let verify_circuit_vk = keygen_vk(&params, circuit).expect("keygen_vk should not fail");

    if let Some(cache_file) = &cache_file_opt {
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        verify_circuit_vk.write(&mut fd).unwrap();
    };

    verify_circuit_vk
}

pub fn load_instance<E: MultiMillerLoop>(n_rows: &[u32], cache_file: &Path) -> Vec<Vec<E::Scalar>> {
    assert!(Path::exists(&cache_file));
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    let mut instances = vec![];
    for n_row in n_rows {
        let mut col = vec![];
        for _ in 0..*n_row {
            col.push(E::Scalar::read(&mut fd).unwrap())
        }
        instances.push(col);
    }
    instances
}

pub fn store_instance<F: FieldExt>(instances: &Vec<Vec<F>>, cache_file: &Path) {
    let mut fd = std::fs::File::create(&cache_file).unwrap();
    for instance_col in instances.iter() {
        for instance in instance_col {
            instance.write(&mut fd).unwrap();
        }
    }
}

pub fn instance_to_instance_commitment<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vk: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<&Vec<Vec<E::Scalar>>>,
) -> Vec<Vec<E::G1Affine>> {
    instances
        .iter()
        .zip(vk.iter())
        .map(|(instances, vk)| {
            instances
                .iter()
                .map(|instance| {
                    assert!(instance.len() <= params.n as usize - (vk.cs.blinding_factors() + 1));

                    params.commit_lagrange(instance.to_vec()).to_affine()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

pub fn load_proof(cache_file: &Path) -> Vec<u8> {
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    let mut buf = vec![];
    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn load_or_create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    vkey: VerifyingKey<E::G1Affine>,
    circuit: C,
    instances: &[&[E::Scalar]],
    cache_file_opt: Option<&Path>,
    hash: TranscriptHash,
    try_load_proof: bool,
    use_shplonk: bool,
) -> Vec<u8> {
    if let Some(cache_file) = &cache_file_opt {
        if try_load_proof && Path::exists(&cache_file) {
            return load_proof(&cache_file);
        }
    }

    let timer = start_timer!(|| "generate pkey");
    let pkey = keygen_pk(params, vkey, &circuit).expect("keygen_pk should not fail");
    end_timer!(timer);

    let timer = start_timer!(|| "create proof");
    let transcript = match hash {
        TranscriptHash::Blake2b => {
            let mut transcript = Blake2bWrite::init(vec![]);
            create_proof_ext(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
                !use_shplonk,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
        TranscriptHash::Poseidon => {
            let mut transcript = PoseidonWrite::init(vec![]);
            create_proof_ext(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
                !use_shplonk,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
        TranscriptHash::Sha => {
            let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
            create_proof_ext(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
                !use_shplonk,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
        TranscriptHash::Keccak => {
            let mut transcript = ShaWrite::<_, _, _, sha3::Keccak256>::init(vec![]);
            create_proof_ext(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
                !use_shplonk,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
    };
    end_timer!(timer);

    if let Some(cache_file) = &cache_file_opt {
        println!("write transcript to {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(&transcript).unwrap();
    };

    transcript
}

/* CARE: unsafe means that to review before used in real production */
pub fn run_circuit_unsafe_full_pass_no_rec<
    E: MultiMillerLoop + G2AffineBaseHelper,
    C: Circuit<E::Scalar>,
>(
    cache_folder: &Path,
    prefix: &str,
    k: u32,
    circuits: Vec<C>,
    instances: Vec<Vec<Vec<E::Scalar>>>,
    fake_instances: Vec<Vec<Vec<E::Scalar>>>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
    expose: Vec<[usize; 2]>,
    max_public_instance: Vec<Vec<usize>>,
    force_create_proof: bool,
) -> Option<(
    AggregatorCircuitOption<E::G1Affine>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
)>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    run_circuit_unsafe_full_pass::<E, C>(
        cache_folder,
        prefix,
        k,
        circuits,
        instances,
        fake_instances,
        force_create_proof,
        &AggregatorConfig::new_for_non_rec(hash, commitment_check, expose, max_public_instance),
    )
}

// t: target circuits, t0 means non-end circuit, t1 means end circuit
// a: aggregatore circuits
pub fn calc_hash<C: CurveAffine>(
    hash_cont: [C::Scalar; 3], // constant_hash of [target_cont], [target_cont, a_init], [target_cont, a_non_init]
    hash_tail: [C::Scalar; 3], // constant_hash of [target_tail], [target_tail, a_init], [target_tail, a_non_init]
    max: usize,
) -> Vec<C::Scalar> {
    let mut res = vec![];

    let mut hasher_cont = PoseidonPure::<C>::default();
    for i in 0..max {
        let mut hasher_tail = hasher_cont.clone();
        hasher_cont
            .common_scalar(*hash_cont.get(i).unwrap_or(&hash_cont[2]))
            .unwrap();
        hasher_tail
            .common_scalar(*hash_tail.get(i).unwrap_or(&hash_tail[2]))
            .unwrap();

        res.push(*hasher_tail.squeeze_challenge_scalar::<()>());

        let hash_cont = *hasher_cont.squeeze_challenge_scalar::<()>();
        hasher_cont.reset();
        hasher_cont.common_scalar(hash_cont).unwrap();
    }

    res
}

pub struct AggregatorConfig<F: FieldExt> {
    pub hash: TranscriptHash,
    pub commitment_check: Vec<[usize; 4]>,
    pub expose: Vec<[usize; 2]>,
    pub absorb: Vec<([usize; 3], [usize; 2])>,
    /* (proof_index, instance_col, hash) */
    pub target_aggregator_constant_hash_instance_offset: Vec<(usize, usize, F)>,
    /* the set of proof that genearted with shplonk (if target_proof_with_shplonk_as_default is false) */
    pub target_proof_with_shplonk: Vec<usize>,
    pub target_proof_with_shplonk_as_default: bool,
    pub target_proof_max_instance: Vec<Vec<usize>>,

    // Absorb instance in each agg.
    // (proof_idx_of_target, columns, proof_idx_of_prev_agg, expose_row)
    pub absorb_instance: Vec<(usize, usize, usize, usize)>,

    // final aggregator is a different aggregator, it merge all instance into a hash
    pub is_final_aggregator: bool,
    // final aggregator skips some instance for hash because they are absorbed thus should be zero
    pub prev_aggregator_skip_instance: Vec<(usize, usize)>,

    // about halo2ecc-s circuit
    pub use_select_chip: bool,
}

impl<F: FieldExt> AggregatorConfig<F> {
    pub fn new_for_non_rec(
        hash: TranscriptHash,
        commitment_check: Vec<[usize; 4]>,
        expose: Vec<[usize; 2]>,
        target_proof_max_instance: Vec<Vec<usize>>,
    ) -> Self {
        Self {
            hash,
            commitment_check,
            expose,
            absorb: vec![],
            target_aggregator_constant_hash_instance_offset: vec![],
            target_proof_with_shplonk: vec![],
            target_proof_with_shplonk_as_default: false,
            target_proof_max_instance,
            is_final_aggregator: true,
            prev_aggregator_skip_instance: vec![],
            absorb_instance: vec![],
            use_select_chip: false,
        }
    }

    pub fn default_aggregator_config(
        hash: TranscriptHash,
        target_proof_max_instance: Vec<Vec<usize>>,
        is_final_aggregator: bool,
    ) -> Self {
        Self {
            hash,
            commitment_check: vec![],
            expose: vec![],
            absorb: vec![],
            target_aggregator_constant_hash_instance_offset: vec![],
            target_proof_with_shplonk: vec![],
            target_proof_with_shplonk_as_default: false,
            target_proof_max_instance,
            is_final_aggregator,
            prev_aggregator_skip_instance: vec![],
            absorb_instance: vec![],
            use_select_chip: !is_final_aggregator,
        }
    }
}

/* CARE: unsafe means that to review before used in production */
pub fn run_circuit_unsafe_full_pass<
    'a,
    E: MultiMillerLoop + G2AffineBaseHelper,
    C: Circuit<E::Scalar>,
>(
    cache_folder: &'a Path,
    prefix: &'a str,
    k: u32,
    circuits: Vec<C>,
    instances: Vec<Vec<Vec<E::Scalar>>>,
    fake_instances: Vec<Vec<Vec<E::Scalar>>>,
    force_create_proof: bool,
    config: &AggregatorConfig<E::Scalar>,
) -> Option<(
    AggregatorCircuitOption<E::G1Affine>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
)>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    let hash = config.hash;

    // 1. setup params
    let params =
        load_or_build_unsafe_params::<E>(k, Some(&cache_folder.join(format!("K{}.params", k))));

    let mut proofs = vec![];
    for (i, circuit) in circuits.into_iter().enumerate() {
        // 2. setup vkey
        let vkey = load_or_build_vkey::<E, C>(
            &params,
            &circuit,
            Some(&cache_folder.join(format!("{}.{}.vkey.data", prefix, i))),
        );

        // 3. create proof
        let proof = load_or_create_proof::<E, C>(
            &params,
            vkey,
            circuit,
            &instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>(),
            Some(&cache_folder.join(format!("{}.{}.transcript.data", prefix, i))),
            config.hash,
            !force_create_proof,
            hash != TranscriptHash::Poseidon
                || config.target_proof_with_shplonk_as_default
                || config.target_proof_with_shplonk.contains(&i),
        );
        proofs.push(proof);

        let mut aligned_instances = instances[i].clone();
        // We need to align instance to max according to config
        for j in 0..instances[i].len() {
            use halo2_proofs::arithmetic::Field;
            assert!(instances[i][j].len() <= config.target_proof_max_instance[i][j]);
            aligned_instances[j].resize(config.target_proof_max_instance[i][j], E::Scalar::zero());
        }
        store_instance(
            &aligned_instances,
            &cache_folder.join(format!("{}.{}.instance.data", prefix, i)),
        );

        if hash != TranscriptHash::Poseidon {
            // Store fake instaces for solidity verifier when create proof for final aggregator.
            assert!(fake_instances.len() > i);
            store_instance(
                &fake_instances[i],
                &cache_folder.join(format!("{}.{}.fakeinstance.data", prefix, i)),
            );
        }
    }

    // 4. many verify
    let public_inputs_size = instances.iter().fold(0usize, |acc, x| {
        usize::max(acc, x.iter().fold(0, |acc, x| usize::max(acc, x.len())))
    });
    let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size + 10).unwrap();

    let mut vkeys = vec![];

    for (i, proof) in proofs.iter().enumerate() {
        let vkey = load_vkey::<E, C>(
            &params,
            &cache_folder.join(format!("{}.{}.vkey.data", prefix, i)),
        );

        // origin check
        if true {
            let use_shplonk = hash != TranscriptHash::Poseidon
                || config.target_proof_with_shplonk_as_default
                || config.target_proof_with_shplonk.contains(&i);
            let timer = start_timer!(|| "origin verify single proof");
            let strategy = SingleVerifier::new(&params_verifier);
            match hash {
                TranscriptHash::Blake2b => verify_proof_ext(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut Blake2bRead::init(&proof[..]),
                    !use_shplonk,
                ),
                TranscriptHash::Poseidon => verify_proof_ext(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut PoseidonRead::init(&proof[..]),
                    !use_shplonk,
                ),
                TranscriptHash::Sha => verify_proof_ext(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha2::Sha256>::init(&proof[..]),
                    !use_shplonk,
                ),
                TranscriptHash::Keccak => verify_proof_ext(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha3::Keccak256>::init(&proof[..]),
                    !use_shplonk,
                ),
            }
            .unwrap();
            end_timer!(timer);
        }

        // native single check
        if true {
            let timer = start_timer!(|| "native verify single proof");
            for (i, proof) in proofs.iter().enumerate() {
                crate::native_verifier::verify_single_proof::<E>(
                    &params_verifier,
                    &vkey,
                    &instances[i],
                    proof.clone(),
                    hash,
                    hash != TranscriptHash::Poseidon || config.target_proof_with_shplonk_as_default,
                    &config.target_proof_with_shplonk,
                );
            }
            end_timer!(timer);
        }

        vkeys.push(vkey);
    }

    // native multi check
    if true {
        let timer = start_timer!(|| "native verify aggregated proofs");
        verify_proofs::<E>(
            &params_verifier,
            &vkeys.iter().map(|x| x).collect::<Vec<_>>()[..],
            instances.iter().collect(),
            proofs.clone(),
            config.hash,
            &config.commitment_check,
            hash != TranscriptHash::Poseidon || config.target_proof_with_shplonk_as_default,
            &config.target_proof_with_shplonk,
        );
        end_timer!(timer);
    }

    // circuit multi check
    if hash == TranscriptHash::Poseidon {
        let timer = start_timer!(|| "build_aggregate_verify_circuit");
        let (circuit, instances, fake_instance, hash) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys[..].iter().collect::<Vec<_>>(),
            instances.iter().collect(),
            proofs,
            config,
        );
        end_timer!(timer);

        Some((circuit, instances, fake_instance, hash))
    } else {
        None
    }
}

/* CARE: unsafe means that to review before used in real production */
pub fn run_circuit_with_agg_unsafe_full_pass<
    E: MultiMillerLoop + G2AffineBaseHelper,
    C: Circuit<E::Scalar>,
>(
    cache_folder: &Path,
    prefix: &str,
    k: u32,
    circuits: Vec<C>,
    mut instances: Vec<Vec<Vec<E::Scalar>>>,
    prev_agg_instance: Vec<E::Scalar>,
    prev_agg_circuit: AggregatorCircuit<E::G1Affine>,
    prev_agg_idx: usize,
    force_create_proof: bool,
    config: &AggregatorConfig<E::Scalar>,
) -> Option<(
    AggregatorCircuitOption<E::G1Affine>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
)>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    // 1. setup params
    let params =
        load_or_build_unsafe_params::<E>(k, Some(&cache_folder.join(format!("K{}.params", k))));

    let mut vkeys = vec![];
    let mut proofs = vec![];

    for (i, circuit) in circuits.into_iter().enumerate() {
        // 2. setup vkey
        let vkey = load_or_build_vkey::<E, C>(
            &params,
            &circuit,
            Some(&cache_folder.join(format!("{}.{}.vkey.data", prefix, i))),
        );
        vkeys.push(vkey.clone());

        // 3. create proof
        let proof = load_or_create_proof::<E, C>(
            &params,
            vkey,
            circuit,
            &instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>(),
            Some(&cache_folder.join(format!("{}.{}.transcript.data", prefix, i))),
            config.hash,
            !force_create_proof,
            config.target_proof_with_shplonk_as_default
                || config.target_proof_with_shplonk.contains(&i),
        );
        proofs.push(proof);

        store_instance(
            &instances[i],
            &cache_folder.join(format!("{}.{}.instance.data", prefix, i)),
        );
    }

    let prev_agg_vkey = load_or_build_vkey::<E, _>(
        &params,
        &prev_agg_circuit,
        Some(&cache_folder.join(format!("{}.agg.{}.vkey.data", prefix, prev_agg_idx))),
    );
    vkeys.push(prev_agg_vkey.clone());

    let prev_agg_proof = load_or_create_proof::<E, _>(
        &params,
        prev_agg_vkey,
        prev_agg_circuit,
        &[&prev_agg_instance[..]][..],
        Some(&cache_folder.join(format!("{}.agg.{}.transcript.data", prefix, prev_agg_idx))),
        config.hash,
        !force_create_proof,
        config.target_proof_with_shplonk_as_default,
    );
    proofs.push(prev_agg_proof);

    instances.push(vec![prev_agg_instance]);
    // 4. many verify
    let public_inputs_size = instances.iter().fold(0usize, |acc, x| {
        usize::max(acc, x.iter().fold(0, |acc, x| usize::max(acc, x.len())))
    });
    let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

    // circuit multi check
    if config.hash == TranscriptHash::Poseidon {
        let timer = start_timer!(|| "build_aggregate_verify_circuit");
        let (circuit, instances, fake_instance, hash) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys[..].iter().collect::<Vec<_>>(),
            instances.iter().collect(),
            proofs,
            config,
        );
        end_timer!(timer);

        Some((circuit, instances, fake_instance, hash))
    } else {
        None
    }
}
