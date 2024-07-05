package main

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type BN254API struct {
	api        frontend.API
	u256Api    *U256API
	fpFieldApi *emulated.Field[emparams.BN254Fp]
	frFieldApi *emulated.Field[emparams.BN254Fr]
	curveApi   *sw_emulated.Curve[emparams.BN254Fp, emparams.BN254Fr]
}

func NewBN254API(
	api frontend.API,
	u256Api *U256API,
) (*BN254API, error) {
	fpFieldApi, err := emulated.NewField[emparams.BN254Fp](api)
	if err != nil {
		return nil, err
	}

	frFieldApi, err := emulated.NewField[emparams.BN254Fr](api)
	if err != nil {
		return nil, err
	}

	curveApi, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return nil, err
	}

	return &BN254API{
		api:        api,
		fpFieldApi: fpFieldApi,
		frFieldApi: frFieldApi,
		curveApi:   curveApi,
		u256Api:    u256Api,
	}, nil
}

func (bn254Api *BN254API) BN254FpToU256(input *emulated.Element[emparams.BN254Fp]) U256 {
	input = bn254Api.fpFieldApi.Reduce(input)
	bits := bn254Api.fpFieldApi.ToBits(input)

	// padding zero
	for i := len(bits); i < 256; i++ {
		bits = append(bits, 0)
	}

	// check overflow bits
	for i := 256; i < len(bits); i++ {
		bn254Api.api.AssertIsEqual(bits[i], 0)
	}

	element := bn254Api.u256Api.FromBits(bits)
	return element
}

func (bn254Api *BN254API) ToBN254Fp(input U256) *emulated.Element[emparams.BN254Fp] {
	var fp emparams.BN254Fp
	bits := bn254Api.u256Api.ToBits(input)

	fpBits := int(fp.NbLimbs() * fp.BitsPerLimb())

	// check overflow bits
	for i := fpBits; i < len(bits); i++ {
		bn254Api.api.AssertIsEqual(bits[i], 0)
	}

	element := bn254Api.fpFieldApi.FromBits(bits...)
	return element
}

func (bn254Api *BN254API) ToBn254Fr(input frontend.Variable) *emulated.Element[emparams.BN254Fr] {
	var fr emparams.BN254Fr
	bits := bn254Api.api.ToBinary(input)

	frBits := int(fr.NbLimbs() * fr.BitsPerLimb())

	// check overflow bits
	for i := frBits; i < len(bits); i++ {
		bn254Api.api.AssertIsEqual(bits[i], 0)
	}

	element := bn254Api.frFieldApi.FromBits(bits...)

	return element
}

func (bn254Api *BN254API) ToBN254Point(point [2]U256) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	x := bn254Api.ToBN254Fp(point[0])
	y := bn254Api.ToBN254Fp(point[1])

	return &sw_emulated.AffinePoint[emparams.BN254Fp]{
		X: *x,
		Y: *y,
	}
}

func (bn254Api *BN254API) AssertOnCurve(
	x U256,
	y U256,
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	point := bn254Api.ToBN254Point([2]U256{x, y})
	bn254Api.curveApi.AssertIsOnCurve(point)

	return point
}

func (bn254Api *BN254API) BN254ScalarMul(
	point *sw_emulated.AffinePoint[emparams.BN254Fp],
	scalar frontend.Variable,
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	scalarFr := bn254Api.ToBn254Fr(scalar)
	p := bn254Api.curveApi.ScalarMul(point, scalarFr)
	return p
}

func (bn254Api *BN254API) BN254FromConstant(
	point [2]big.Int,
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	x := emulated.ValueOf[emparams.BN254Fp](point[0])
	y := emulated.ValueOf[emparams.BN254Fp](point[1])
	return &sw_emulated.AffinePoint[emparams.BN254Fp]{
		X: x,
		Y: y,
	}
}

func (bn254Api *BN254API) BN254ScalarMulConstant(
	point [2]big.Int,
	scalar frontend.Variable,
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	p := bn254Api.BN254FromConstant(point)
	scalarFr := bn254Api.ToBn254Fr(scalar)
	return bn254Api.curveApi.ScalarMul(p, scalarFr)
}

func (bn254Api *BN254API) BN254AddG1(
	a *sw_emulated.AffinePoint[emparams.BN254Fp],
	b *sw_emulated.AffinePoint[emparams.BN254Fp],
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	return bn254Api.curveApi.Add(a, b)
}

func (bn254Api *BN254API) BN254ScalarMulAndAddG1(
	point *sw_emulated.AffinePoint[emparams.BN254Fp],
	scalar frontend.Variable,
	b *sw_emulated.AffinePoint[emparams.BN254Fp],
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	a := bn254Api.BN254ScalarMul(point, scalar)
	return bn254Api.curveApi.Add(a, b)
}
