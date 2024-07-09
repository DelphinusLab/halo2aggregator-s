package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"reflect"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	gnarkio "github.com/consensys/gnark/io"
	"github.com/consensys/gnark/test/unsafekzg"
)

var (
	DIR                 = "gnark_setup"
	Groth16PkPath       = fmt.Sprintf("%s/groth16_pk", DIR)
	Groth16VkPath       = fmt.Sprintf("%s/groth16_vk", DIR)
	Groth16VerifierPath = fmt.Sprintf("%s/contract_groth16.sol", DIR)

	PlonkPkPath          = fmt.Sprintf("%s/plonk_pk", DIR)
	PlonkVkPath          = fmt.Sprintf("%s/plonk_vk", DIR)
	PlonkVerifierPath    = fmt.Sprintf("%s/contract_plonk.sol", DIR)
	PlonkSrsName         = fmt.Sprintf("%s/plonk_srs", DIR)
	PlonkSrsLagrangeName = fmt.Sprintf("%s/plonk_srsLagrange", DIR)
)

func GeneratePkVk(cs constraint.ConstraintSystem, prover backend.ID) (any, any) {
	var pk, vk any
	var err error
	switch prover {
	case backend.GROTH16:
		pk, vk, err = groth16.Setup(cs)
		if err != nil {
			log.Fatalln(err)
		}
	case backend.PLONK:
		var srs, srsLagrange kzg.SRS
		if _, err := os.Stat(PlonkSrsName); errors.Is(err, os.ErrNotExist) {
			srs, srsLagrange, err := unsafekzg.NewSRS(cs)
			if err != nil {
				panic(err)
			}
			fSrs, err := os.Create(PlonkSrsName)
			if err != nil {
				log.Fatalln(err)
			}
			_, err = srs.WriteRawTo(fSrs)
			if err != nil {
				log.Fatalln(err)
			}
			fSrsLagrange, err := os.Create(PlonkSrsLagrangeName)
			if err != nil {
				log.Fatalln(err)
			}
			_, err = srsLagrange.WriteRawTo(fSrsLagrange)
			if err != nil {
				log.Fatalln(err)
			}
		} else {
			fSrs, err := os.Open(PlonkSrsName)
			if err != nil {
				log.Fatalln(err)
			}
			_, err = srs.ReadFrom(fSrs)
			if err != nil {
				log.Fatalln(err)
			}
			fSrsLagrange, err := os.Open(PlonkSrsLagrangeName)
			if err != nil {
				log.Fatalln(err)
			}
			_, err = srsLagrange.ReadFrom(fSrsLagrange)
			if err != nil {
				log.Fatalln(err)
			}
		}
		pk, vk, err = plonk.Setup(cs, srs, srsLagrange)
		if err != nil {
			log.Fatalln(err)
		}
	default:
		panic("unhandled default case")
	}
	SavePkVk(pk.(gnarkio.WriterRawTo), vk.(gnarkio.WriterRawTo), prover)
	return pk, vk
}

func SavePkVk(pk, vk gnarkio.WriterRawTo, id backend.ID) {
	var pkPath, vkPath string
	switch id {
	case backend.GROTH16:
		pkPath = Groth16PkPath
		vkPath = Groth16VkPath
	case backend.PLONK:
		pkPath = PlonkPkPath
		vkPath = PlonkVkPath
	default:
		panic("unhandled default case")
	}

	fpk, err := os.Create(pkPath)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = pk.WriteRawTo(fpk)
	if err != nil {
		log.Fatalln(err)
	}

	fvk, err := os.Create(vkPath)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = vk.WriteRawTo(fvk)
	if err != nil {
		log.Fatalln(err)
	}
}

func ReadPkVk(id backend.ID, curveID ecc.ID) (any, any) {
	var pk, vk io.ReaderFrom
	var pkPath, vkPath string
	switch id {
	case backend.GROTH16:
		pkPath = Groth16PkPath
		vkPath = Groth16VkPath
		pk = groth16.NewProvingKey(curveID)
		vk = groth16.NewVerifyingKey(curveID)
	case backend.PLONK:
		pkPath = Groth16PkPath
		vkPath = Groth16VkPath
		pk = plonk.NewProvingKey(curveID)
		vk = plonk.NewVerifyingKey(curveID)
	default:
		panic("unhandled default case")
	}

	fpk, err := os.Open(pkPath)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = pk.ReadFrom(fpk)
	if err != nil {
		log.Fatalln(err)
	}

	fvk, err := os.Open(vkPath)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = vk.ReadFrom(fvk)
	if err != nil {
		log.Fatalln(err)
	}
	return pk, vk
}

// Compile the given circuit for given curve and backend, if not already present in cache
func Compile(circuit frontend.Circuit, curveID ecc.ID, backendID backend.ID, compileOpts []frontend.CompileOption) (constraint.ConstraintSystem, error) {
	var newBuilder frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newBuilder = r1cs.NewBuilder
	case backend.PLONK:
		newBuilder = scs.NewBuilder
	default:
		panic("not implemented")
	}

	// else compile it and ensure it is deterministic
	ccs, err := frontend.Compile(curveID.ScalarField(), newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.Compile(curveID.ScalarField(), newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.New("compilation is not deterministic"), err)
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		return nil, errors.New("compilation is not deterministic")
	}

	return ccs, nil
}

type fnSetup func(ccs constraint.ConstraintSystem, curve ecc.ID) (any, any, error)
type fnProve func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error)
type fnVerify func(proof, vk any, publicWitness witness.Witness, opts ...backend.VerifierOption) error

// Backend abstracts the backend implementation in the test package.
type Backend struct {
	Setup  fnSetup
	Prove  fnProve
	Verify fnVerify
}

var (
	GrothBackend = Backend{
		Setup: func(ccs constraint.ConstraintSystem, curve ecc.ID) (any, any, error) {
			if _, err := os.Stat("gnark_setup"); os.IsNotExist(err) {
				if err := os.Mkdir("gnark_setup", os.ModePerm); err != nil {
					panic(err)
				}
			}
			pk, vk := GeneratePkVk(ccs, backend.GROTH16)
			return pk, vk, nil
		},
		Prove: func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error) {
			return groth16.Prove(ccs, pk.(groth16.ProvingKey), fullWitness, opts...)
		},
		Verify: func(proof, vk any, publicWitness witness.Witness, opts ...backend.VerifierOption) error {
			return groth16.Verify(proof.(groth16.Proof), vk.(groth16.VerifyingKey), publicWitness, opts...)
		},
	}

	PlonkBackend = Backend{
		Setup: func(ccs constraint.ConstraintSystem, curve ecc.ID) (any, any, error) {
			if _, err := os.Stat("gnark_setup"); os.IsNotExist(err) {
				if err := os.Mkdir("gnark_setup", os.ModePerm); err != nil {
					panic(err)
				}
			}
			pk, vk := GeneratePkVk(ccs, backend.GROTH16)
			return pk, vk, nil
		},
		Prove: func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error) {
			return plonk.Prove(ccs, pk.(plonk.ProvingKey), fullWitness, opts...)
		},
		Verify: func(proof, vk any, publicWitness witness.Witness, opts ...backend.VerifierOption) error {
			return plonk.Verify(proof.(plonk.Proof), vk.(plonk.VerifyingKey), publicWitness, opts...)
		},
	}
)

func SolidityVerification(
	b backend.ID, vk solidity.VerifyingKey,
	proof any,
	publicWitness witness.Witness,
	opts []solidity.ExportOption,
) {
	var contractPath string
	var verifyCallData func(proofHex, inputHex string)
	switch b {
	case backend.GROTH16:
		contractPath = Groth16VerifierPath
		verifyCallData = groth16VerifyCallData
	case backend.PLONK:
		contractPath = PlonkVerifierPath
		verifyCallData = plonkVerifyCallData
	default:
		panic("unhandled default case")
	}

	// export solidity contract
	fSolidity, err := os.Create(contractPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = vk.ExportSolidity(fSolidity, opts...)
	if err != nil {
		log.Fatalln(err)
	}
	err = fSolidity.Close()
	if err != nil {
		log.Fatalln(err)
	}

	// len(vk.K) - 1 == len(publicWitness) + len(commitments)
	numOfCommitments := vk.NbPublicWitness() - len(publicWitness.Vector().(fr_bn254.Vector))

	checkerOpts := []string{"verify"}
	if b == backend.GROTH16 {
		checkerOpts = append(checkerOpts, "--groth16")
	} else if b == backend.PLONK {
		checkerOpts = append(checkerOpts, "--plonk")
	} else {
		panic("not implemented")
	}

	// proof to hex
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}

	proofStr := hex.EncodeToString(_proof.MarshalSolidity())

	if numOfCommitments > 0 {
		checkerOpts = append(checkerOpts, "--commitment", strconv.Itoa(numOfCommitments))
	}

	// public witness to hex
	bPublicWitness, err := publicWitness.MarshalBinary()
	// that's quite dirty...
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr := hex.EncodeToString(bPublicWitness)

	verifyCallData(proofStr, publicWitnessStr)
}

func groth16VerifyCallData(proofHex, inputHex string) {
	const (
		fpSize = 4 * 8
	)

	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		log.Fatalln(err)
	}

	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		log.Fatalln(err)
	}

	if len(inputBytes)%fr_bn254.Bytes != 0 {
		panic("inputBytes mod fr.Bytes !=0")
	}

	// convert public inputs
	nbInputs := len(inputBytes) / fr_bn254.Bytes
	input := make([]*big.Int, nbInputs)
	for i := 0; i < nbInputs; i++ {
		var e fr_bn254.Element
		e.SetBytes(inputBytes[fr_bn254.Bytes*i : fr_bn254.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
	}

	// solidity contract inputs
	var proof [8]*big.Int

	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		proof[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}

	// prepare commitments for calling
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(c.Int64())

	if commitmentCount != 1 {
		panic("commitmentCount != .NbCommitments")
	}

	var commitments [2]*big.Int
	var commitmentPok [2]*big.Int

	// commitments
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	outputBigIntArray("proof", proof[:])
	outputBigIntArray("commitments", commitments[:])
	outputBigIntArray("commitmentPoks", commitmentPok[:])
	outputBigIntArray("inputs", input[:])
}

func plonkVerifyCallData(proofHex, inputHex string) {
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		log.Fatalln(err)
	}
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		log.Fatalln(err)
	}

	if len(inputBytes)%fr_bn254.Bytes != 0 {
		panic("inputBytes mod fr.Bytes !=0")
	}

	// convert public inputs
	nbInputs := len(inputBytes) / fr_bn254.Bytes
	input := make([]*big.Int, nbInputs)
	for i := 0; i < nbInputs; i++ {
		var e fr_bn254.Element
		e.SetBytes(inputBytes[fr_bn254.Bytes*i : fr_bn254.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
	}

	log.Println("proof:", hex.EncodeToString(proofBytes))
	outputBigIntArray("input", input)
}

func outputBigIntArray(hint string, res []*big.Int) {
	fmt.Printf("%s: [", hint)
	for i := 0; i < len(res); i++ {
		fmt.Print(res[i].String())
		if i != len(res)-1 {
			fmt.Print(",")
		}
	}
	fmt.Print("]\n")
}
