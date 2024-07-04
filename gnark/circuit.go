package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"

	"fmt"
	"math/big"
)

type Halo2VerifierCircuit struct {
	config   Halo2VerifierConfig
	Proof    []frontend.Variable
	Instance []frontend.Variable `gnark:",public"`
}

type Halo2VerifierAPI struct {
	config   Halo2VerifierConfig
	api      frontend.API
	u64Api   *uints.BinaryField[uints.U64]
	u256Api  *U256API
	bn254Api *BN254API
}

func NewHalo2VerifierAPI(config Halo2VerifierConfig, api frontend.API, u64Api *uints.BinaryField[uints.U64], u256Api *U256API, bn254Api *BN254API) Halo2VerifierAPI {
	return Halo2VerifierAPI{
		config:   config,
		api:      api,
		u64Api:   u64Api,
		u256Api:  u256Api,
		bn254Api: bn254Api,
	}
}

func (halo2Api *Halo2VerifierAPI) calcSingleInstanceCommitment(index int, instance frontend.Variable) (*sw_emulated.AffinePoint[emparams.BN254Fp], error) {
	x, succeed := new(big.Int).SetString(halo2Api.config.VerifyCircuitGLagrange[index][0], 10)
	if !succeed {
		return nil, fmt.Errorf("invalid x in VerifyCircuitGLagrange at %d, with value %s", index, halo2Api.config.VerifyCircuitGLagrange[index][0])
	}
	y, succeed := new(big.Int).SetString(halo2Api.config.VerifyCircuitGLagrange[index][1], 10)
	if !succeed {
		return nil, fmt.Errorf("invalid y in VerifyCircuitGLagrange at %d, with value %s", index, halo2Api.config.VerifyCircuitGLagrange[index][1])
	}

	return halo2Api.bn254Api.BN254ScalarMulConstant([2]big.Int{*x, *y}, instance), nil
}

func (halo2Api *Halo2VerifierAPI) calcInstanceCommitment(instances []frontend.Variable) (*sw_emulated.AffinePoint[emparams.BN254Fp], error) {
	acc, err := halo2Api.calcSingleInstanceCommitment(0, instances[0])
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(instances); i++ {
		p, err := halo2Api.calcSingleInstanceCommitment(i, instances[i])
		if err != nil {
			return nil, err
		}

		acc = halo2Api.bn254Api.BN254AddG1(acc, p)
	}
	return acc, nil
}

func (halo2Api *Halo2VerifierAPI) proofToU256(proof []frontend.Variable) ([]U256, error) {
	if len(proof)%32 != 0 {
		return nil, fmt.Errorf("invalid proof size")
	}

	transcript := make([]U256, len(proof)/32)
	for i := range transcript {
		for j := 0; j < 4; j++ {
			for k := 0; k < 8; k++ {
				transcript[i][j][k] = halo2Api.u64Api.ByteValueOf(proof[i*32+j*8+k])
			}
		}
	}

	return transcript, nil
}

func (circuit *Halo2VerifierCircuit) Define(api frontend.API) error {
	u64Api, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	u256Api := NewU256API(api, u64Api)

	bn254Api, err := NewBN254API(api, u256Api)
	if err != nil {
		return err
	}

	halo2Api := NewHalo2VerifierAPI(circuit.config, api, u64Api, u256Api, bn254Api)

	transcript, err := halo2Api.proofToU256(circuit.Proof)
	if err != nil {
		return err
	}

	instanceCommitment, err := halo2Api.calcInstanceCommitment(circuit.Instance)
	if err != nil {
		return err
	}

	_, _, err = halo2Api.getChallengesShPlonkCircuit(instanceCommitment, transcript)
	if err != nil {
		return err
	}

	/*
	   buf, err = VerifyProof(api, circuit.Proof, buf)

	   	if err != nil {
	   		return err
	   	}

	   	for i := 10; i < 14; i++ {
	   		err = api.AssertIsDifferent(buf[i], 0)
	   		if err != nil {
	   			return err
	   		}
	   	}

	   g1Points, err := FillVerifyCircuitsG1(api, buf[10], buf[11], buf[12], buf[13])

	   	if err != nil {
	   		return err
	   	}

	   g2Points := FillVerifyCircuitsG2()

	   // Do pairing
	   pairing, err := sw_bn254.NewPairing(api)

	   	if err != nil {
	   		return fmt.Errorf("NewPairing: %w", err)
	   	}

	   err = pairing.PairingCheck(

	   	g1Points,
	   	g2Points,

	   )

	   	if err != nil {
	   		return fmt.Errorf("pair: %w", err)
	   	}
	*/

	return nil
}
