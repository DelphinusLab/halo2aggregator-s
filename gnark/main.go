// Welcome to the gnark playground!
package main

import (
	"encoding/json"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func loadProofStr() ([]string, error) {
	data, err := os.ReadFile("proof.data")
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

func loadInstanceStr() ([]string, error) {
	data, err := os.ReadFile("instance.data")
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

func loadHalo2VerifierConfig() (Halo2VerifierConfig, error) {
	res := Halo2VerifierConfig{}

	data, err := os.ReadFile("aggregator_config.json")
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
	proofStr, err := loadProofStr()
	if err != nil {
		panic(err)
	}

	instanceStr, err := loadInstanceStr()
	if err != nil {
		panic(err)
	}

	config, err := loadHalo2VerifierConfig()
	if err != nil {
		panic(err)
	}

	aggCircuit := Halo2VerifierCircuit{
		config:   config,
		Proof:    make([]frontend.Variable, len(proofStr)),
		Instance: make([]frontend.Variable, len(instanceStr)),
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &aggCircuit)
	if err != nil {
		panic(err)
	}

	// 1. Setup
	if _, err := os.Stat("gnark_setup"); os.IsNotExist(err) {
		os.Mkdir("gnark_setup", os.ModePerm)
	}

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	if _, err := os.Stat("gnark_setup/groth16_pk"); os.IsNotExist(err) {
		log.Println("[Start] setup")

		pk, vk, err := groth16.Setup(r1cs)
		if err != nil {
			panic(err)
		}

		fpk, err := os.Create("gnark_setup/groth16_pk")
		if err != nil {
			log.Fatalln(err)
		}
		_, err = pk.WriteRawTo(fpk)
		if err != nil {
			log.Fatalln(err)
		}

		fvk, err := os.Create("gnark_setup/groth16_vk")
		if err != nil {
			log.Fatalln(err)
		}
		_, err = vk.WriteRawTo(fvk)
		if err != nil {
			log.Fatalln(err)
		}

		// Generate solidity code on setup
		f, err := os.Create("gnark_setup/contract_groth16.sol")
		if err != nil {
			log.Fatalln(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			log.Fatalln(err)
		}

		log.Println("[End] setup")
	} else {
		log.Println("[Start] load pk vk")

		fpk, err := os.Open("gnark_setup/groth16_pk")
		if err != nil {
			log.Fatalln(err)
		}
		pk := groth16.NewProvingKey(ecc.BN254)
		_, err = pk.ReadFrom(fpk)
		if err != nil {
			log.Fatalln(err)
		}
		fvk, err := os.Open("gnark_setup/groth16_vk")
		if err != nil {
			log.Fatalln(err)
		}
		vk := groth16.NewVerifyingKey(ecc.BN254)
		_, err = vk.ReadFrom(fvk)
		if err != nil {
			log.Fatalln(err)
		}

		log.Println("[End] load pk vk")
	}

	// 2a. Fill witness and instance
	witnessCircuit := Halo2VerifierCircuit{
		Proof:    make([]frontend.Variable, len(proofStr)),
		Instance: make([]frontend.Variable, 1),
	}

	for i := 0; i < len(proofStr); i++ {
		proof, _ := big.NewInt(0).SetString(proofStr[i], 10)
		witnessCircuit.Proof[i] = proof
	}

	for i := 0; i < len(instanceStr); i++ {
		instance, _ := big.NewInt(0).SetString(instanceStr[i], 10)
		witnessCircuit.Instance[i] = instance
	}

	// 2b. Generate r1cs witness
	witness, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	// 3. Generate Proof
	log.Println("[Start] prove")

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}
	proofJSON, _ := json.MarshalIndent(proof, "", "    ")
	_ = os.WriteFile("gnark_proof.json", proofJSON, 0644)
	fProof, err := os.Create("proof")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = proof.WriteRawTo(fProof)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("[End] proof")

	// 4. Verify proof
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

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	log.Println("[End] verify")
}
