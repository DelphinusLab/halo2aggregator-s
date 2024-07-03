package main

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/crypto"
)

func (config AggregatorConfig) CalcSingleInstanceCommitment(api frontend.API, index int, buf frontend.Variable) (BN254AffinePoint, error) {
	x, err := NewU256(new(big.Int).SetString(config.VerifyCircuitLagrangeCommitments[index][0], 10))
	if err != nil {
		return err
	}

	y, err := NewU256(new(big.Int).SetString(config.VerifyCircuitLagrangeCommitments[index][1], 10))
	if err != nil {
		return err
	}

	res, err := BN254ScalarMulOnConstPoint(api, [2]big.int{x, y}, buf[2])
	if err != nil {
		return err
	}

	return res, err
}

func (config AggregatorConfig) CalcInstanceCommitment(api frontend.API, buf []frontend.Variable) (BN254AffinePoint, error) {
	x, err := NewU256(new(big.Int).SetString(config.VerifyCircuitLagrangeCommitments[0][0], 10))
	if err != nil {
		return err
	}

	y, err := NewU256(new(big.Int).SetString(config.VerifyCircuitLagrangeCommitments[0][1], 10))
	if err != nil {
		return err
	}

	res, err := BN254ScalarMulOnConstPoint(api, [2]big.int{x, y}, buf[2])
	if err != nil {
		return err
	}

	return res, err
}

type AggregatorCircuit struct {
	Proof []frontend.Variable
	Inst  []frontend.Variable `gnark:",public"`
}

func proofToU256(api frontend.API, proof []frontend.Variable) ([]U256, error) {
	if len(proof) % 4 != 0 {
		return nil, fmt.Errorf("invalid proof size")
	}

	u64Api, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}

	transcript := make([]U256, len(Proof) / 4)
	for i := range transcript {
		transcript[i][0] = u64Api.ValueOf(proof[i * 4])
		transcript[i][1] = u64Api.ValueOf(proof[i * 4 + 1])
		transcript[i][2] = u64Api.ValueOf(proof[i * 4 + 2])
		transcript[i][3] = u64Api.ValueOf(proof[i * 4 + 3])
	}

	return transcript, nil
}

func (circuit *AggregatorCircuit) Define(api frontend.API) error {
	// Use U256 because Fp modulus > Fq modulus in BN254
	buf := new([128]U256)
	transcript, err := proofToU256(api, circuit.Proof)

	buf[2], err := ToU256(api, circuit.Inst[0])

	err = CalcVerifyCircuitLagrange(api, buf[:])
	if err != nil {
		return err
	}

	err = GetChallengesShPlonkCircuit(api, buf[:], circuit.Proof)
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
}
