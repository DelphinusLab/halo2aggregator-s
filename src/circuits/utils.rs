use crate::circuit_verifier::build_aggregate_verify_circuit;
use crate::circuit_verifier::circuit::AggregatorCircuit;
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
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::create_proof_with_shplonk;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::verify_proof_with_shplonk;
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

pub(crate) static USE_GWC_FOR_TARGET_PROOF: bool = true;

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
            create_proof(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
        TranscriptHash::Poseidon => {
            let mut transcript = PoseidonWrite::init(vec![]);
            create_proof(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
        TranscriptHash::Sha => {
            let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
            create_proof_with_shplonk(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
            )
            .expect("proof generation should not fail");
            transcript.finalize()
        }
        TranscriptHash::Keccak => {
            let mut transcript = ShaWrite::<_, _, _, sha3::Keccak256>::init(vec![]);
            create_proof(
                params,
                &pkey,
                &[circuit],
                &[instances],
                OsRng,
                &mut transcript,
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
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
    expose: Vec<[usize; 2]>,
    force_create_proof: bool,
) -> Option<(AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>, E::Scalar)>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    run_circuit_unsafe_full_pass::<E, C>(
        cache_folder,
        prefix,
        k,
        circuits,
        instances,
        hash,
        commitment_check,
        expose,
        vec![],
        force_create_proof,
        &vec![],
    )
}

// t: target circuits, t0 means non-end circuit, t1 means end circuit
// a: aggregatore circuits
pub fn calc_hash<C: CurveAffine>(
    t1_hash: C::Scalar, // end on first
    t0_hash: C::Scalar,
    t1_a0_hash: C::Scalar, // end on second
    t0_a0_hash: C::Scalar,
    t1_a1_hash: C::Scalar, // end on third
    t0_a1_hash: C::Scalar,
    max: usize,
) -> Vec<C::Scalar> {
    let mut res = vec![t1_hash];
    let mut last = t0_hash;

    let hasher_default = PoseidonPure::<C>::default();
    let mut hasher_end = hasher_default.clone();
    let mut hasher_next = hasher_default;

    for i in 1..max {
        hasher_next.common_scalar(last).unwrap();
        hasher_end.common_scalar(last).unwrap();

        if i == 1 {
            hasher_end.common_scalar(t1_a0_hash).unwrap();
            hasher_next.common_scalar(t0_a0_hash).unwrap();
        } else {
            hasher_end.common_scalar(t1_a1_hash).unwrap();
            hasher_next.common_scalar(t0_a1_hash).unwrap();
        }

        res.push(*hasher_end.squeeze_challenge_scalar::<()>());
        last = *hasher_next.squeeze_challenge_scalar::<()>();

        hasher_next.reset();
        hasher_end.reset();
    }

    res
}

/* CARE: unsafe means that to review before used in real production */
pub fn run_circuit_unsafe_full_pass<
    E: MultiMillerLoop + G2AffineBaseHelper,
    C: Circuit<E::Scalar>,
>(
    cache_folder: &Path,
    prefix: &str,
    k: u32,
    circuits: Vec<C>,
    instances: Vec<Vec<Vec<E::Scalar>>>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
    expose: Vec<[usize; 2]>,
    absorb: Vec<([usize; 3], [usize; 2])>,
    force_create_proof: bool,
    target_aggregator_constant_hash_instance_offset: &Vec<(usize, usize, E::Scalar)>, // (proof_index, instance_col, hash)
) -> Option<(AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>, E::Scalar)>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
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
            hash,
            !force_create_proof,
        );
        proofs.push(proof);

        store_instance(
            &instances[i],
            &cache_folder.join(format!("{}.{}.instance.data", prefix, i)),
        );
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
            let timer = start_timer!(|| "origin verify single proof");
            let strategy = SingleVerifier::new(&params_verifier);
            match hash {
                TranscriptHash::Blake2b => verify_proof(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut Blake2bRead::init(&proof[..]),
                ),
                TranscriptHash::Poseidon => verify_proof(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut PoseidonRead::init(&proof[..]),
                ),
                TranscriptHash::Sha => verify_proof_with_shplonk(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha2::Sha256>::init(&proof[..]),
                ),
                TranscriptHash::Keccak => verify_proof(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha3::Keccak256>::init(&proof[..]),
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
                    hash == TranscriptHash::Poseidon && USE_GWC_FOR_TARGET_PROOF,
                );
            }
            end_timer!(timer);
        }

        // circuit single check
        if hash == TranscriptHash::Poseidon {
            let timer = start_timer!(|| "build_single_proof_verify_circuit");
            for (i, proof) in proofs.iter().enumerate() {
                let (circuit, instances, _) =
                    crate::circuit_verifier::build_single_proof_verify_circuit::<E>(
                        &params_verifier,
                        &vkey,
                        &instances[i],
                        proof.clone(),
                        hash,
                        expose.clone(),
                        absorb.clone(),
                        target_aggregator_constant_hash_instance_offset,
                        USE_GWC_FOR_TARGET_PROOF,
                    );
                const K: u32 = 21;
                let prover = MockProver::run(K, &circuit, vec![instances]).unwrap();
                assert_eq!(prover.verify(), Ok(()));
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
            hash,
            commitment_check.clone(),
            hash == TranscriptHash::Poseidon && USE_GWC_FOR_TARGET_PROOF,
        );
        end_timer!(timer);
    }

    // circuit multi check
    if hash == TranscriptHash::Poseidon {
        let timer = start_timer!(|| "build_aggregate_verify_circuit");
        let (circuit, instances, hash) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys[..].iter().collect::<Vec<_>>(),
            instances.iter().collect(),
            proofs,
            hash,
            commitment_check,
            expose,
            absorb,
            target_aggregator_constant_hash_instance_offset,
            USE_GWC_FOR_TARGET_PROOF,
        );
        end_timer!(timer);

        if false {
            const K: u32 = 21;
            let prover = MockProver::run(K, &circuit, vec![instances.clone()]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }

        Some((circuit, instances, hash))
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
    agg_circuit: AggregatorCircuit<E::G1Affine>,
    last_agg_instance: Vec<E::Scalar>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
    expose: Vec<[usize; 2]>,
    absorb: Vec<([usize; 3], [usize; 2])>,
    force_create_proof: bool,
    target_aggregator_constant_hash_instance_offset: &Vec<(usize, usize, E::Scalar)>, // (proof_index, instance_col, hash)
    agg_idx: usize,
) -> Option<(AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>, E::Scalar)>
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
            hash,
            !force_create_proof,
        );
        proofs.push(proof);

        store_instance(
            &instances[i],
            &cache_folder.join(format!("{}.{}.instance.data", prefix, i)),
        );
    }

    let agg_vkey = load_or_build_vkey::<E, _>(
        &params,
        &agg_circuit,
        Some(&cache_folder.join(format!("{}.agg.{}.vkey.data", prefix, agg_idx))),
    );
    vkeys.push(agg_vkey.clone());

    let agg_proof = load_or_create_proof::<E, _>(
        &params,
        agg_vkey,
        agg_circuit,
        &[&last_agg_instance[..]][..],
        Some(&cache_folder.join(format!("{}.agg.{}.transcript.data", prefix, agg_idx))),
        hash,
        !force_create_proof,
    );
    proofs.push(agg_proof);

    instances.push(vec![last_agg_instance]);
    // 4. many verify
    let public_inputs_size = instances.iter().fold(0usize, |acc, x| {
        usize::max(acc, x.iter().fold(0, |acc, x| usize::max(acc, x.len())))
    });
    let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

    // circuit multi check
    if hash == TranscriptHash::Poseidon {
        let timer = start_timer!(|| "build_aggregate_verify_circuit");
        let (circuit, instances, hash) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys[..].iter().collect::<Vec<_>>(),
            instances.iter().collect(),
            proofs,
            hash,
            commitment_check,
            expose,
            absorb,
            target_aggregator_constant_hash_instance_offset,
            false,
        );
        end_timer!(timer);

        if false {
            const K: u32 = 21;
            let prover = MockProver::run(K, &circuit, vec![instances.clone()]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }

        Some((circuit, instances, hash))
    } else {
        None
    }
}
