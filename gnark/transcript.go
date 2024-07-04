package main

func squeezeChallenge(
	api frontend.API,
	sha2Api hash.BinaryFixedLengthHasher,
	absorbing *[]uints.U8,
	challenges *[]frontend.Variable,
) {
	for i := 0; i < 32; i++ {
		*absorbing = append(*absorbing, 0)
	}

	sha2Api.Write(absorbing)
	res := h.Sum()
	if len(res) != 32 {
		panic("sha2 returned value not 32 bytes")
	}

	base := big.NewInt(1)
	sum := res[0]
	for i := 1; i < 32; i++ {
		base = base.Lsh(8)
		sum = api.Add(sum, api.Mul(res[i], base))
	}

	*absorbing = res
	*challenges = append(*challenges, sum)
}

func commonU256(
	api frontend.API,
	absorbing *[]uints.U8,
	transcript *[]U256,
) {
	for i := range transcript[0] {
		for j := range transcript[0][i] {
			*absorbing = append(*absorbing, transcript[0][i][j])
		}
	}

	*transcript = *transcript[1:]
}

func commonScalar(
	api frontend.API,
	absorbing *[]uints.U8,
	transcript *[]U256,
) {
	commonU256(api, absorbing, transcript)
}

func commonPoint(
	api frontend.API,
	bn254Api BN254API,
	absorbing *[]uints.U8,
	transcript *[]U256,
	commitments *[]BN254AffinePoint,
) {
	p := bn254Api.AssertOnCurve(api, *points[0], *points[1])
	*commitments = append(*commitments, p)

	commonU256(api, absorbing, transcript)
	commonU256(api, absorbing, transcript)
}

func (config AggregatorConfig) GetChallengesShPlonkCircuit(
	api frontend.API,
	bn254Api BN254API,
	instanceCommitment []U256,
	transcript []U256,
) ([]frontend.Variable, []BN254AffinePoint, error) {
	sha2Api, err := sha2.New(api)
	if err != nil {
		return err
	}

	absorbing := []frontend.U8{}
	challenges := []frontend.Variable{}
	commitments := []BN254AffinePoint{}

	challengeInitScalar := new(big.Int).SetString(AggregatorConfig.ChallengeInitScalar, 10)
	{
		bytes := make([]byte, 32)
		bytes = challengeInitScalar.FillBytes(bytes)
		for i := 0; i < 32; i++ {
			absorbing = append(absorbing, uints.New8(bytes[i]))
		}
	}

	// TODO common instanceCommitment
	// commonPoint(api, bn254Api, absorbing, instanceCommitment)

	opSeq := [][3]int{
		[3]int{config.NbAdvices, 1, 0},                                 // theta
		[3]int{config.NbLookups * 2, 2, 0},                             // beta, gamma
		[3]int{config.NbPermutationGroup + config.NbLookups + 1, 1, 0}, // y
		[3]int{config.Degree, 1, config.nbEvals},                       // x
		[3]int{0, 2, 0},                                                // y, v in multiopen
		[3]int{1, 1, 0},                                                //u in multiopen
	}

	for i := range opSeq {
		for j := 0; j < opSeq[i][0]; j++ {
			commonPoint(api, bn254Api, absorbing, transcript, commitments)
		}

		for j := 0; j < opSeq[i][1]; j++ {
			squeezeChallenge(api, sha2Api, absorbing, challenges)
		}

		for j := 0; j < opSeq[i][2]; j++ {
			commonScalar(api, absorbing, transcript)
		}
	}

	bn254Api.AssertOnCurve(api, transcript[i:i+2])
}
