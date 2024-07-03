package main

func squeezeChallenge(
	api frontend.API,
	absorbing *[]uints.U8,
	challenges *[]frontend.Variable,
) error {
	for i := 0; i < 32; i++ {
		*absorbing = append(*absorbing, 0)
	}

	sha2Api, err := sha2.New(api)
	if err != nil {
		return err
	}

	sha2Api.Write(absorbing)
	res := h.Sum()
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}

	base := big.NewInt(1)
	sum := res[0]
	for i := 1; i < 32; i++ {
		base = base.Lsh(8)
		sum = api.Add(sum, api.Mul(res[i], base))
	}

	*absorbing = res
	*challenges = append(*challenges, sum)

	return nil
}

func commonScalar(
	api frontend.API,
	absorbing *[]uints.U8,
	transcript *[]uints.U64,
) {
	for i := 0; i < 4; i++ {
		*absorbing = append(*absorbing, transcript[i])
	}

	*transcript = *transcript[4:]

	return nil
}

func commonPoint(
	api frontend.API,
	absorbing *[]uints.U8,
	points *[]uints.U64,
) error {
	err := AssertOnCurve(api, *points[0:8])
	if err != nil {
		return err
	}

	for i := 0; i < 8; i++ {
		*absorbing = append(*absorbing, points[i])
	}
	*points = *points[8:]

	return nil
}

func (config AggregatorConfig) GetChallengesShPlonkCircuit(
	api frontend.API,
	instance []uints.U64,
	transcript []uints.U64,
) ([]frontend.Variable, error) {
	absorbing := []frontend.U8{}
	challenges := []frontend.Variable{}

	challengeInitScalar := new(big.Int).SetString(AggregatorConfig.ChallengeInitScalar, 10)
	{
		bytes := make([]byte, 32)
		bytes = challengeInitScalar.FillBytes(bytes)
		for i := 0; i < 32; i++ {
			absorbing = append(absorbing, uints.New8(bytes[i]))
		}
	}

	err = commonPoint(api, absorbing, instance)
	if err != nil {
		return err
	}

	for i := 0; i < config.NbAdvices; i++ {
		err = commonPoint(api, absorbing, transcript)
		if err != nil {
			return err
		}
	}

	// theta
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	for i := 0; i < config.NbLookups*2; i++ {
		err = commonPoint(api, absorbing, transcript)
		if err != nil {
			return err
		}
	}

	// beta
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	// gamma
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	for i := 0; i < config.NbPermutationGroup+config.NbLookups+1; i++ {
		err = commonPoint(api, absorbing, transcript)
		if err != nil {
			return err
		}
	}

	// y
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	for i := 0; i < config.Degree; i++ {
		err = commonPoint(api, absorbing, transcript)
		if err != nil {
			return err
		}
	}

	//x
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	for i := 0; i < config.nbEvals; i++ {
		err = commonScalar(api, absorbing, transcript)
		if err != nil {
			return err
		}
	}

	//y in multiopen
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	//v in multiopen
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}
	err = commonPoint(api, absorbing, transcript)
	if err != nil {
		return err
	}

	//u in multiopen
	err = squeezeChallenge(api, absorbing, challenges)
	if err != nil {
		return err
	}

	if len(transcript) != 8 {
		panic("invalid proof size")
	}

	err = AssertOnCurve(api, transcript[i:i+8])
	if err != nil {
		return err
	}
}
