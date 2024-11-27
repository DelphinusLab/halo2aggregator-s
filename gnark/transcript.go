package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
)

func squeezeChallenge(
	api frontend.API,
	absorbing *[]uints.U8,
	challenges *[]frontend.Variable,
) error {
	*absorbing = append(*absorbing, uints.NewU8(0))

	sha2Api, err := sha2.New(api)
	if err != nil {
		return err
	}

	sha2Api.Write(*absorbing)
	res := sha2Api.Sum()
	if len(res) != 32 {
		panic("sha2 returned value not 32 bytes")
	}

	// Pack bytes in BE
	base := big.NewInt(1)
	sum := res[31].Val
	for i := 1; i < 32; i++ {
		base = base.Lsh(base, 8)
		sum = api.Add(sum, api.Mul(res[31-i].Val, base))
	}

	*absorbing = res
	*challenges = append(*challenges, sum)

	return nil
}

func commonU256(
	api frontend.API,
	absorbing *[]uints.U8,
	x U256,
) {
	// Append bytes in BE
	for i := 3; i >= 0; i-- {
		for j := 7; j >= 0; j-- {
			*absorbing = append(*absorbing, x[i][j])
		}
	}
}

func commonScalar(
	api frontend.API,
	absorbing *[]uints.U8,
	transcript *[]U256,
) {
	commonU256(api, absorbing, (*transcript)[0])
	*transcript = (*transcript)[1:]
}

func commonPoint(
	api frontend.API,
	bn254Api *BN254API,
	absorbing *[]uints.U8,
	transcript *[]U256,
	commitments *[]*sw_emulated.AffinePoint[emparams.BN254Fp],
) {
	p := bn254Api.AssertOnCurve((*transcript)[0], (*transcript)[1])
	*commitments = append(*commitments, p)

	commonU256(api, absorbing, (*transcript)[0])
	commonU256(api, absorbing, (*transcript)[1])
	*transcript = (*transcript)[2:]
}

// Return challenges and commitments
func (halo2Api *Halo2VerifierAPI) getChallengesShPlonkCircuit(
	instanceCommitments []*sw_emulated.AffinePoint[emparams.BN254Fp],
	transcript []U256,
) ([]frontend.Variable, []*sw_emulated.AffinePoint[emparams.BN254Fp], []frontend.Variable, error) {
	var absorbing []uints.U8
	var challenges []frontend.Variable
	var commitments []*sw_emulated.AffinePoint[emparams.BN254Fp]
	var evals []frontend.Variable

	challengeInitScalar, succeed := new(big.Int).SetString(halo2Api.config.ChallengeInitScalar, 10)
	if !succeed {
		return challenges, commitments, evals, fmt.Errorf("invalid ChallengeInitScalar %s", halo2Api.config.ChallengeInitScalar)
	}
	{
		bytes := make([]byte, 32)
		bytes = challengeInitScalar.FillBytes(bytes)
		for i := 0; i < 32; i++ {
			absorbing = append(absorbing, uints.NewU8(bytes[i]))
		}
	}

	for i := range instanceCommitments {
		commonU256(halo2Api.api, &absorbing, halo2Api.bn254Api.BN254FpToU256(&(*instanceCommitments[i]).X))
		commonU256(halo2Api.api, &absorbing, halo2Api.bn254Api.BN254FpToU256(&(*instanceCommitments[i]).Y))
	}

	opSeq := [][3]uint32{
		{halo2Api.config.NbAdvices, 1, 0},                                           // theta
		{halo2Api.config.NbLookupsM, 2, 0},                                       // beta, gamma
		{halo2Api.config.NbPermutationGroups + halo2Api.config.NbLookupsZs + 1, 1, 0}, // y
		{halo2Api.config.Degree, 1, halo2Api.config.NbEvals},                        // x
		{0, 2, 0}, // y, v in multiopen
		{1, 1, 0}, // u in multiopen
		{1, 0, 0}, //
	}

	for i := range opSeq {
		for j := uint32(0); j < opSeq[i][0]; j++ {
			commonPoint(halo2Api.api, halo2Api.bn254Api, &absorbing, &transcript, &commitments)
		}

		for j := uint32(0); j < opSeq[i][1]; j++ {
			err := squeezeChallenge(halo2Api.api, &absorbing, &challenges)
			if err != nil {
				return challenges, commitments, evals, err
			}
		}

		for j := uint32(0); j < opSeq[i][2]; j++ {
			evals = append(evals, halo2Api.u256Api.ToValue(transcript[0]))
			commonScalar(halo2Api.api, &absorbing, &transcript)
		}
	}

	return challenges, commitments, evals, nil
}
