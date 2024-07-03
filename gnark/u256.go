package main

type U256 [4]uints.U64

func U256ToBits(
	api frontend.API,
	x U256,
) []frontend.Variable {
	bits := []frontend.Variable{}
	for i := range x {
		for j := range x[i] {
			bits = append(bits, api.ToBinary(x[i][j].Val, 8))
		}
	}
	return bits
}

/*
func ToU256Hint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	bytes := make([]byte, 32)
	bytes = input[0].FillBytes(bytes)

	for i := 0; i < 4; i++ {
		outputs[i] = new(big.Int).SetBytes(bytes[i*8 : i*8+8])
	}

	return nil
}

func NewU256(
	x big.int,
) U256 {
	bytes := make([]byte, 32)
	bytes = x.FillBytes(bytes)

	res := new(U256)

	res[0] = new(big.int).FillBytes(bytes[0:8])
	res[1] = new(big.int).FillBytes(bytes[8:16])
	res[2] = new(big.int).FillBytes(bytes[16:24])
	res[3] = new(big.int).FillBytes(bytes[24:])

	return res
}

func ToU256(
	api frontend.API,
	x frontend.Variable,
) (U256, error) {
	u64Arr, err := api.Compiler().NewHint(ToU256Hint, 4, x)
	if err != nil {
		return nil, err
	}

	base := big.NewInt(1)
	sum := u64Arr[0]
	for i := 1; i < 4; i++ {
		base = base.Lsh(64)
		sum = api.Add(sum, api.Mul(u64Arr[i], base))
	}
	api.AssertIsEqual(sum, x)

	u64Api, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	res := new(U256)
	res[0] = u64Api.ValueOf(u64Arr[0])
	res[1] = u64Api.ValueOf(u64Arr[1])
	res[2] = u64Api.ValueOf(u64Arr[2])
	res[3] = u64Api.ValueOf(u64Arr[3])

	return res, nil
}


func U64FromBits(
	api frontend.API,
	u64Api *BinaryField[U64],
	bits []frontend.Variable,
) U64 {
	u64Api, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}

	u64Api.ValueOf(api.FromBinary(bits[0:64]))

}

func U256FromBits(
	api frontend.API,
	bits []frontend.Variable,
) (U256, error) {
	u64Api, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}

	res := new(U256)
	res[0] = U64FromBits(api, u64Api, bits[0:64])
	res[1] = U64FromBits(api, u64Api, bits[64:128])
	res[2] = U64FromBits(api, u64Api, bits[128:196])
	res[3] = U64FromBits(api, u64Api, bits[196:256])

	return res, nil
}
*/