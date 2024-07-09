// Welcome to the gnark playground!
package main

import (
	"crypto/sha256"
	"encoding/json"
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
		backendID       = backend.GROTH16
		curveID         = ecc.BN254
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
	pk, vk, err := concreteBackend.Setup(ccs, curveID)
	if err != nil {
		panic(err)
	}

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
