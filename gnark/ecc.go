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
	bits := bn254Api.fpFieldApi.ToBits(input)

	// padding zero
	for i := len(bits); i < 256; i++ {
		bits = append(bits, new(big.Int).SetUint64(0))
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

	// padding zero
	for i := len(bits); i < fpBits; i++ {
		bits = append(bits, new(big.Int).SetUint64(0))
	}

	// check overflow bits
	for i := fpBits; i < len(bits); i++ {
		bn254Api.api.AssertIsEqual(bits[i], 0)
	}

	element := bn254Api.fpFieldApi.FromBits(bits)
	return element
}

func (bn254Api *BN254API) ToBn254Fr(input frontend.Variable) *emulated.Element[emparams.BN254Fr] {
	var fr emparams.BN254Fr
	bits := bn254Api.api.ToBinary(input)

	frBits := int(fr.NbLimbs() * fr.BitsPerLimb())
	// padding zero
	for i := len(bits); i < frBits; i++ {
		bits = append(bits, new(big.Int).SetUint64(0))
	}

	// check overflow bits
	for i := frBits; i < len(bits); i++ {
		bn254Api.api.AssertIsEqual(bits[i], 0)
	}

	element := bn254Api.frFieldApi.FromBits(bits)
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

func (bn254Api *BN254API) BN254ScalarMulConstant(
	point [2]big.Int,
	scalar frontend.Variable,
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	x := emulated.ValueOf[emparams.BN254Fp](point[0])
	y := emulated.ValueOf[emparams.BN254Fp](point[1])
	ps := sw_emulated.AffinePoint[emparams.BN254Fp]{
		X: x,
		Y: y,
	}

	scalarFr := bn254Api.ToBn254Fr(scalar)
	p := bn254Api.curveApi.ScalarMul(&ps, scalarFr)
	return p
}

func (bn254Api *BN254API) BN254AddG1(
	a *sw_emulated.AffinePoint[emparams.BN254Fp],
	b *sw_emulated.AffinePoint[emparams.BN254Fp],
) *sw_emulated.AffinePoint[emparams.BN254Fp] {
	return bn254Api.curveApi.Add(a, b)
}

/*
func U256FromElement[T emulated.FieldParams](api frontend.API, input emulated.Element[T]) (U256, error) {
	var fp = T

	fieldApi, err := emulated.NewField[T](api)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	reducedInput := fieldApi.reduce(input)
	bits := fieldApi.toBits(reducedInput)

	// Ensure overflow bits are zero
	sum := 0
	for i := 256; i < fp.NbLimbs()*fp.BitsPerLimb(); i++ {
		sum = api.Add(sum, bits[i])
	}
	api.AssertIsEqual(sum, 0)

	// Padding zero
	for i := fp.NbLimbs() * fp.BitsPerLimb(); i < 256; i++ {
		bits = append(bits, 0)
	}

	output = U256FromBits(api, bits)

	return output, nil
}

func U256ToElement[T emulated.FieldParams](api frontend.API, input U256) (emulated.Element[T], error) {
	var fp = T

	fieldApi, err := emulated.NewField[T](api)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	bits := U256ToBits(api, input)

	// padding zero
	for i := len(bits); i < fp.NbLimbs()*fp.BitsPerLimb(); i++ {
		bits = append(bits, new(big.Int).SetUint64(0))
	}

	// check overflow bits
	for i := fp.NbLimbs() * fp.BitsPerLimb(); i < len(bits); i++ {
		api.AssertIsEqual(bits[i], 0)
	}

	element := fieldApi.FromBits(bits)
	return element, nil
}


func ToPoint[T emulated.FieldParams](api frontend.API, point [2]U256) (sw_emulated.AffinePoint[T], error) {
	x, err := U256ToElement[T](api, point[0])
	if err != nil {
		return sw_emulated.AffinePoint[T]{}, err
	}
	y, err := U256ToElement[T](api, point[1])
	if err != nil {
		return sw_emulated.AffinePoint[T]{}, err
	}

	return sw_emulated.AffinePoint[T]{
		X: x,
		Y: y,
	}, nil
}

func BN254ScalarMul(
	api frontend.API,
	point [2]U256,
	scalar frontend.Variable,
) (sw_emulated.AffinePoint[emparams.BN254Fp], error) {
	curveApi, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}

	ps, err := ToPoint[emulated.BN254Fp](api, point)
	if err != nil {
		return err
	}

	scalarEle, err := VarToElement[emulated.BN254Fr](api, scalar)
	if err != nil {
		return err
	}

	p := curveApi.ScalarMul(&ps, &scalarEle)
	return p, nil
}


func BN254ScalarMulOnConstPoint(
	api frontend.API,
	point [2]big.int,
	scalar frontend.Variable,
) (sw_emulated.AffinePoint[emparams.BN254Fp], error) {
	curveApi, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}

	x := emulated.ValueOf[emparams.BN254Fp](point[0])
	y := emulated.ValueOf[emparams.BN254Fp](point[1])
	p := sw_emulated.AffinePoint[emparams.BN254Fp]{
		X: x,
		Y: y,
	}

	scalarEle, err := VarToElement[emulated.BN254Fr](api, scalar)
	if err != nil {
		return err
	}

	p = curveApi.ScalarMul(&p, &scalarEle)
	return res, nil
}


func AssertOnCurve(
	api frontend.API,
	x U256,
	y U256,
) error {
	curveApi, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}

	point, err := ToPoint[emulated.BN254Fp](api, [2]U256{x, y})
	if err != nil {
		return err
	}
	curveApi.AssertIsOnCurve(&point)

	return nil
}
*/
