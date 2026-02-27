// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"math/big"
	"testing"
)

var TOLERANCE = big.NewInt(1_000_000_000)

func mustBig(s string) *big.Int {
	z, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad big int literal: " + s)
	}
	return z
}

func takeFee(x *big.Int) *big.Int {
	// x * (10000 - fee) / 10000
	num := new(big.Int).Mul(x, big.NewInt(BPS_DENOM-FEE_RATE_BPS))
	return new(big.Int).Div(num, big.NewInt(BPS_DENOM))
}

func absDiff(a, b *big.Int) *big.Int {
	return new(big.Int).Abs(new(big.Int).Sub(a, b))
}

func TestCreatorModel(t *testing.T) {
	totalSupply := new(big.Int).Mul(big.NewInt(1_000_000_000), WAD)
	startPrice := mustBig("583400000000000") // WAD
	endPrice := mustBig("9749900000000000")  // WAD
	type TestCase struct {
		grossInvestmentWad *big.Int
		expectedTokensWad  *big.Int
		expectedSpotWad    *big.Int
		expectedNetBaseWad *big.Int
	}
	tests := []TestCase{
		{
			grossInvestmentWad: mustBig("1000000000000000000"),
			expectedTokensWad:  mustBig("1679807989817709328076"),
			expectedSpotWad:    mustBig("583400027890610"),
			expectedNetBaseWad: mustBig("960399999999999999"),
		},
		{
			grossInvestmentWad: mustBig("33333333333333000000"),
			expectedTokensWad:  mustBig("55993394666396529818306"),
			expectedSpotWad:    mustBig("583405367521085"),
			expectedNetBaseWad: mustBig("32013333333333013199"),
		},
		{
			grossInvestmentWad: mustBig("333333333333330000000"),
			expectedTokensWad:  mustBig("559870862207721253827562"),
			expectedSpotWad:    mustBig("583569707236276"),
			expectedNetBaseWad: mustBig("320133333333330131999"),
		},
		{
			grossInvestmentWad: mustBig("3333333333333300000000"),
			expectedTokensWad:  mustBig("5578940742559168288416181"),
			expectedSpotWad:    mustBig("588738216521435"),
			expectedNetBaseWad: mustBig("3201333333333301319999"),
		},
		{
			grossInvestmentWad: mustBig("33333333333333000000000"),
			expectedTokensWad:  mustBig("50867726484859642305131984"),
			expectedSpotWad:    mustBig("730371136811535"),
			expectedNetBaseWad: mustBig("32013333333333013199999"),
		},
		{
			grossInvestmentWad: mustBig("330000000000000000000000"),
			expectedTokensWad:  mustBig("257836815644399703352708261"),
			expectedSpotWad:    mustBig("2260604255342097"),
			expectedNetBaseWad: mustBig("316931999999999999999999"),
		},
	}

	passed := 0
	m := &creatorModel{}
	for i, tc := range tests {
		// 1) buy: fee deducted from investment before passing to QuoteBuyOut
		otherBalance := new(big.Int).Set(totalSupply)
		netInvestment := takeFee(tc.grossInvestmentWad)

		tokensOut := m.QuoteBuyOut(netInvestment, big.NewInt(0), otherBalance, startPrice, endPrice)

		// 2) spot price after purchase
		soldTokens := new(big.Int).Set(tokensOut)
		otherAfter := new(big.Int).Sub(otherBalance, soldTokens)
		spot := m.CurrentPrice(soldTokens, otherAfter, startPrice, endPrice)

		// 3) sell all back, then fee on base out
		baseOut := m.QuoteSellOut(soldTokens, soldTokens, otherAfter, startPrice, endPrice)
		netBaseOut := takeFee(baseOut)

		okTokens := absDiff(tokensOut, tc.expectedTokensWad).Cmp(TOLERANCE) <= 0
		okSpot := absDiff(spot, tc.expectedSpotWad).Cmp(TOLERANCE) <= 0
		okBase := absDiff(netBaseOut, tc.expectedNetBaseWad).Cmp(TOLERANCE) <= 0

		if !okTokens && !okSpot && !okBase {
			t.Fail()
		}

		fmt.Printf(
			"[%d] %s | tokens=%v spot=%v netBase=%v\n",
			i+1, "OK", okTokens, okSpot, okBase,
		)
	}

	fmt.Printf("Results: %d passed, %d failed (tolerance=%s)\n", passed, len(tests)-passed, TOLERANCE.String())
}
