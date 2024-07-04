package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"

	"encoding/binary"
	"math/big"
)

type U256 [4]uints.U64

type U256API struct {
	api    frontend.API
	u64Api *uints.BinaryField[uints.U64]
}

func NewU256API(api frontend.API, u64Api *uints.BinaryField[uints.U64]) *U256API {
	return &U256API{
		api:    api,
		u64Api: u64Api,
	}
}

func (u256Api *U256API) ToBits(
	x U256,
) []frontend.Variable {
	bits := []frontend.Variable{}
	for i := range x {
		for j := range x[i] {
			bits = append(bits, u256Api.api.ToBinary(x[i][j].Val, 8)...)
		}
	}
	return bits
}

func U64FromBits(
	api frontend.API,
	u64Api *uints.BinaryField[uints.U64],
	bits []frontend.Variable,
) uints.U64 {
	if u64Api == nil {
		panic("u64Api")
	}
	return u64Api.ValueOf(api.FromBinary(bits...))
}

func (u256Api *U256API) FromBits(
	bits []frontend.Variable,
) U256 {
	res := U256{}
	res[0] = U64FromBits(u256Api.api, u256Api.u64Api, bits[0:64])
	res[1] = U64FromBits(u256Api.api, u256Api.u64Api, bits[64:128])
	res[2] = U64FromBits(u256Api.api, u256Api.u64Api, bits[128:192])
	res[3] = U64FromBits(u256Api.api, u256Api.u64Api, bits[192:256])
	return res
}

func NewU256(
	x big.Int,
) U256 {
	bytes := make([]byte, 32)
	bytes = x.FillBytes(bytes)

	res := U256{}

	res[0] = uints.NewU64(binary.LittleEndian.Uint64(bytes[0:8]))
	res[1] = uints.NewU64(binary.LittleEndian.Uint64(bytes[8:16]))
	res[2] = uints.NewU64(binary.LittleEndian.Uint64(bytes[16:24]))
	res[3] = uints.NewU64(binary.LittleEndian.Uint64(bytes[24:]))

	return res
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



*/
