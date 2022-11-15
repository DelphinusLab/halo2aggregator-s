use ark_std::end_timer;
use ark_std::rand::rngs::OsRng;
use ark_std::start_timer;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Blake2bWrite;
use std::io::Read;
use std::io::Write;
use std::path::Path;

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

pub fn load_or_build_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    circuit: &C,
    cache_file_opt: Option<&Path>,
) -> VerifyingKey<E::G1Affine> {
    if let Some(cache_file) = &cache_file_opt {
        if Path::exists(&cache_file) {
            println!("read vkey from {:?}", cache_file);
            let mut fd = std::fs::File::open(&cache_file).unwrap();
            return VerifyingKey::read::<_, C>(&mut fd, params).unwrap();
        }
    }

    let verify_circuit_vk = keygen_vk(&params, circuit).expect("keygen_vk should not fail");

    if let Some(cache_file) = &cache_file_opt {
        println!("write vkey to {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        verify_circuit_vk.write(&mut fd).unwrap();
    };

    verify_circuit_vk
}

pub fn load_instance<E: MultiMillerLoop>(n_rows: &[u32], cache_file: &Path) -> Vec<Vec<E::Scalar>> {
    assert!(Path::exists(&cache_file));
    println!("read instance from {:?}", cache_file);
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

pub fn store_instance<E: MultiMillerLoop>(instances: Vec<Vec<E::Scalar>>, cache_file: &Path) {
    println!("write instance to {:?}", cache_file);
    let mut fd = std::fs::File::create(&cache_file).unwrap();
    for instance_col in instances.iter() {
        for instance in instance_col {
            instance.write(&mut fd).unwrap();
        }
    }
}

pub enum TranscriptHash {
    Blake2b,
}

pub fn load_or_create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    vkey: VerifyingKey<E::G1Affine>,
    circuit: C,
    instances: &[&[E::Scalar]],
    cache_file_opt: Option<&Path>,
    hash: TranscriptHash,
) -> Vec<u8> {
    if let Some(cache_file) = &cache_file_opt {
        if Path::exists(&cache_file) {
            println!("read transcript from {:?}", cache_file);
            let mut fd = std::fs::File::open(&cache_file).unwrap();
            let mut buf = vec![];
            fd.read_to_end(&mut buf).unwrap();
            return buf;
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
pub fn run_circuit_unsafe_full_pass<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    cache_folder: &Path,
    prefix: &str,
    k: u32,
    circuit: C,
    instances: Vec<Vec<E::Scalar>>,
    hash: TranscriptHash,
) {
    let params =
        load_or_build_unsafe_params::<E>(k, Some(&cache_folder.join(format!("K{}.params", k))));

    let circuit_without_witness = circuit.without_witnesses();

    let vkey = load_or_build_vkey::<E, C>(
        &params,
        &circuit_without_witness,
        Some(&cache_folder.join(format!("{}.vkey.data", prefix))),
    );

    let proof = load_or_create_proof::<E, C>(
        &params,
        vkey,
        circuit,
        &instances.iter().map(|x| &x[..]).collect::<Vec<_>>(),
        Some(&cache_folder.join(format!("{}.transcript.data", prefix))),
        hash,
    );

    if true {
        let vkey = load_or_build_vkey::<E, C>(
            &params,
            &circuit_without_witness,
            Some(&cache_folder.join(format!("{}.vkey.data", prefix))),
        );

        let public_inputs_size = instances
            .iter()
            .fold(0usize, |acc, x| usize::max(acc, x.len()));
        let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

        let strategy = SingleVerifier::new(&params_verifier);
        let timer = start_timer!(|| "verify proof");

        verify_proof(
            &params_verifier,
            &vkey,
            strategy,
            &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
            &mut Blake2bRead::init(&proof[..]),
        )
        .unwrap();
        end_timer!(timer);
    }
}
