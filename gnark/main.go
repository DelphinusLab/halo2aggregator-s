// Welcome to the gnark playground!
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	gnarkio "github.com/consensys/gnark/io"
)

func loadProofData() (Halo2VerifierProofData, error) {
	var res Halo2VerifierProofData

	data, err := os.ReadFile("halo2_verifier_proof.json")
	if err != nil {
		return res, err
	}

	err = json.Unmarshal(data, &res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func loadHalo2VerifierConfig() (Halo2VerifierConfig, error) {
	var res Halo2VerifierConfig

	data, err := os.ReadFile("halo2_verifier_config.json")
	if err != nil {
		return res, err
	}

	err = json.Unmarshal(data, &res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func main() {
	var backendIDString, curveIDString string
	var isSetup bool

	flag.StringVar(&backendIDString, "backendID", "GROTH16", "Specify the backend ID (e.g., PLONK, GROTH16)")
	flag.StringVar(&curveIDString, "curveID", "BN254", "Specify the curve ID (e.g., BN254, BLS12_381)")
	flag.BoolVar(&isSetup, "setup", true, "Whether to setup to generate pk,vk")
	flag.Parse()

	backendID, err := parseBackendID(backendIDString)
	if err != nil {
		log.Fatalf("Invalid backendID: %v", err)
	}

	curveID, err := parseCurveID(curveIDString)
	if err != nil {
		log.Fatalf("Invalid curveID: %v", err)
	}

	proofData, err := loadProofData()
	if err != nil {
		panic(err)
	}

	config, err := loadHalo2VerifierConfig()
	if err != nil {
		panic(err)
	}

	defalutInstance := make([][]frontend.Variable, len(proofData.Instance))
	for i := range proofData.Instance {
		defalutInstance[i] = make([]frontend.Variable, len(proofData.Instance[i]))
	}
	halo2VerifierCircuit := Halo2VerifierCircuit{
		config:     config,
		Instance:   defalutInstance,
		Transcript: make([]frontend.Variable, len(proofData.Transcript)),
	}

	var (
		concreteBackend Backend
	)

	// 1. compile
	log.Println("[Start] Compile")
	ccs, err := Compile(&halo2VerifierCircuit, curveID, backendID, []frontend.CompileOption{frontend.IgnoreUnconstrainedInputs()})
	if err != nil {
		panic(err)
	}
	log.Println("[End] Compile")

	switch backendID {
	case backend.GROTH16:
		concreteBackend = GrothBackend
	case backend.PLONK:
		concreteBackend = PlonkBackend
	default:
		panic("backend not implemented")
	}

	// 2. setup
	log.Println("[Start] Setup")
	pk, vk, err := concreteBackend.Setup(ccs, curveID, isSetup)
	if err != nil {
		panic(err)
	}
	log.Println("[End] Setup")

	var proverOpts []backend.ProverOption
	var verifierOpts []backend.VerifierOption
	if backendID == backend.GROTH16 {
		// additionally, we use sha256 as hash to field (fixed in Solidity contract)
		proverOpts = append(proverOpts, backend.WithProverHashToFieldFunction(sha256.New()))
		verifierOpts = append(verifierOpts, backend.WithVerifierHashToFieldFunction(sha256.New()))
	}

	succeed := true

	// 3a. Fill witness and instance
	instance := make([][]frontend.Variable, len(proofData.Instance))
	for i := range proofData.Instance {
		instance[i] = make([]frontend.Variable, len(proofData.Instance[i]))
		for j := range proofData.Instance[i] {
			instance[i][j], succeed = big.NewInt(0).SetString(proofData.Instance[i][j], 10)
			if !succeed {
				_ = fmt.Errorf("invalid instance", proofData.Instance[i][j])
			}
		}
	}
	transcript := make([]frontend.Variable, len(proofData.Transcript))
	for i := range proofData.Transcript {
		transcript[i], succeed = big.NewInt(0).SetString(proofData.Transcript[i], 10)
		if !succeed {
			_ = fmt.Errorf("invalid transcript", proofData.Transcript[i])
		}
	}

	witnessCircuit := Halo2VerifierCircuit{
		config:     config,
		Transcript: transcript,
		Instance:   instance,
	}

	// 3b. Generate witness
	witness, err := frontend.NewWitness(&witnessCircuit, curveID.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	// 4. Generate Proof
	log.Println("[Start] prove")

	proof, err := concreteBackend.Prove(ccs, pk, witness, proverOpts...)
	if err != nil {
		log.Fatalln(err)
	}
	proofJSON, _ := json.MarshalIndent(proof, "", "    ")
	_ = os.WriteFile("gnark_proof.json", proofJSON, 0644)
	fProof, err := os.Create("proof")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = proof.(gnarkio.WriterRawTo).WriteRawTo(fProof)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("[End] proof")

	// 5. Verify Proof
	log.Println("[Start] verify")

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	s, err := frontend.NewSchema(&witnessCircuit)
	if err != nil {
		panic(err)
	}
	publicWitnessJSON, err := publicWitness.ToJSON(s)
	_ = os.WriteFile("gnark_inputs.json", publicWitnessJSON, 0644)
	fPublic, err := os.Create("public")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = publicWitness.WriteTo(fPublic)
	if err != nil {
		log.Fatalln(err)
	}

	err = concreteBackend.Verify(proof, vk, publicWitness, verifierOpts...)
	if err != nil {
		panic(err)
	}

	log.Println("[End] verify")

	SolidityVerification(backendID, vk.(solidity.VerifyingKey), proof, publicWitness, nil)
}

func parseBackendID(backendIDString string) (backend.ID, error) {
	switch backendIDString {
	case "PLONK":
		return backend.PLONK, nil
	case "GROTH16":
		return backend.GROTH16, nil
	default:
		return 0, fmt.Errorf("unsupported backend ID: %s", backendIDString)
	}
}

func parseCurveID(curveIDString string) (ecc.ID, error) {
	switch curveIDString {
	case "BN254":
		return ecc.BN254, nil
	case "BLS12_381":
		return ecc.BLS12_381, nil
	default:
		return 0, fmt.Errorf("unsupported curve ID: %s", curveIDString)
	}
}
