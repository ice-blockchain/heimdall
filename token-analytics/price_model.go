// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
)

type (
	pricingModel interface {
		QuoteBuyOut(amountInBase, soldTokens, otherBalance, startPrice, endPrice *big.Int) *big.Int
		CurrentPrice(soldTokens, otherBalance, startPrice, endPrice *big.Int) *big.Int
		QuoteSellOut(amountInOther, soldTokens, otherBalance, startPrice, endPrice *big.Int) *big.Int
	}
	creatorModel struct {
	}
)

var priceModel pricingModel = &creatorModel{}

var (
	WAD         = big.NewInt(1_000_000_000_000_000_000) // 1e18
	TRADABLEBPS = int64(8000)                           // 80%
	BPS_DENOM   = int64(10_000)

	FEE_RATE_BPS = int64(200) // 2%
)

func sqrtFloor(n *big.Int) *big.Int {
	if n.Sign() < 0 {
		panic("sqrtFloor: negative input")
	}
	return new(big.Int).Sqrt(n) // Go 1.20+
}

// pow1_5Wad computes (x/scale)^1.5 * WAD, all integer math.
// (x/scale)^1.5 = (x*sqrt(x)) / (scale*sqrt(scale))
// sqrt approximated at WAD precision via sqrt(x*WAD).
func pow1_5Wad(x, scale *big.Int) *big.Int {
	if x.Sign() == 0 || scale.Sign() == 0 {
		return new(big.Int)
	}

	// num = x * isqrt(x*WAD)
	xWad := new(big.Int).Mul(x, WAD)
	sx := sqrtFloor(xWad)
	num := new(big.Int).Mul(x, sx)

	// denom = scale * isqrt(scale*WAD)
	scaleWad := new(big.Int).Mul(scale, WAD)
	ss := sqrtFloor(scaleWad)
	denom := new(big.Int).Mul(scale, ss)
	if denom.Sign() == 0 {
		return new(big.Int)
	}

	// return num * WAD / denom
	return new(big.Int).Div(new(big.Int).Mul(num, WAD), denom)
}

// reserveAtWad computes cumulative reserve R(s) (WAD) for supply s (WAD).
func reserveAtWad(s, sCurve, mStart, mDiff, totalSupply *big.Int) *big.Int {
	if totalSupply.Sign() == 0 {
		return new(big.Int)
	}

	// term1 = mStart * s / totalSupply
	term1 := new(big.Int).Div(new(big.Int).Mul(mStart, s), totalSupply)

	// ratio = (s/sCurve)^1.5 * WAD
	ratio := pow1_5Wad(s, sCurve)
	if ratio.Sign() == 0 || s.Sign() == 0 || mDiff.Sign() == 0 {
		return term1
	}

	// term2 = mDiff * ratio / WAD * s / totalSupply * 2 / 5
	term2 := new(big.Int).Div(new(big.Int).Mul(mDiff, ratio), WAD)
	term2.Div(new(big.Int).Mul(term2, s), totalSupply)
	term2.Div(new(big.Int).Mul(term2, big.NewInt(2)), big.NewInt(5))

	return new(big.Int).Add(term1, term2)
}

func (c *creatorModel) QuoteBuyOut(amountInBase, soldTokens, otherBalance, startPrice, endPrice *big.Int) *big.Int {
	totalSupply := new(big.Int).Add(soldTokens, otherBalance)

	sCurve := new(big.Int).Div(
		new(big.Int).Mul(totalSupply, big.NewInt(TRADABLEBPS)),
		big.NewInt(BPS_DENOM),
	)

	// mStart = startPrice * totalSupply / WAD
	mStart := new(big.Int).Div(new(big.Int).Mul(startPrice, totalSupply), WAD)
	// mEnd = endPrice * totalSupply / WAD
	mEnd := new(big.Int).Div(new(big.Int).Mul(endPrice, totalSupply), WAD)
	mDiff := new(big.Int).Sub(mEnd, mStart)

	s1 := new(big.Int).Set(soldTokens)

	r1 := reserveAtWad(s1, sCurve, mStart, mDiff, totalSupply)
	targetR2 := new(big.Int).Add(r1, amountInBase)

	maxR := reserveAtWad(sCurve, sCurve, mStart, mDiff, totalSupply)
	if targetR2.Cmp(maxR) > 0 {
		// remaining tradable inventory = otherBalance - (totalSupply - sCurve)
		nonTradable := new(big.Int).Sub(totalSupply, sCurve)
		return new(big.Int).Sub(otherBalance, nonTradable)
	}

	low := new(big.Int).Set(s1)
	high := new(big.Int).Set(sCurve)

	for i := 0; i < 256; i++ {
		mid := new(big.Int).Div(new(big.Int).Add(low, high), big.NewInt(2))
		rMid := reserveAtWad(mid, sCurve, mStart, mDiff, totalSupply)

		if rMid.Cmp(targetR2) < 0 {
			low = mid
		} else {
			high = mid
		}

		if new(big.Int).Sub(high, low).Cmp(big.NewInt(1)) <= 0 {
			break
		}
	}

	s2 := new(big.Int).Div(new(big.Int).Add(low, high), big.NewInt(2))
	return new(big.Int).Sub(s2, s1)
}

func (c *creatorModel) CurrentPrice(soldTokens, otherBalance, startPrice, endPrice *big.Int) *big.Int {
	totalSupply := new(big.Int).Add(soldTokens, otherBalance)

	sCurve := new(big.Int).Div(
		new(big.Int).Mul(totalSupply, big.NewInt(TRADABLEBPS)),
		big.NewInt(BPS_DENOM),
	)

	ratio := pow1_5Wad(soldTokens, sCurve)
	priceDiff := new(big.Int).Sub(endPrice, startPrice)

	// spot = start + diff*ratio/WAD
	return new(big.Int).Add(
		startPrice,
		new(big.Int).Div(new(big.Int).Mul(priceDiff, ratio), WAD),
	)
}

func (c *creatorModel) QuoteSellOut(amountInOther, soldTokens, otherBalance, startPrice, endPrice *big.Int) *big.Int {
	if amountInOther.Sign() == 0 {
		return new(big.Int)
	}
	if soldTokens.Cmp(amountInOther) < 0 {
		panic("QuoteSellOut: amountInOther > soldTokens")
	}

	totalSupply := new(big.Int).Add(soldTokens, otherBalance)

	sCurve := new(big.Int).Div(
		new(big.Int).Mul(totalSupply, big.NewInt(TRADABLEBPS)),
		big.NewInt(BPS_DENOM),
	)

	mStart := new(big.Int).Div(new(big.Int).Mul(startPrice, totalSupply), WAD)
	mEnd := new(big.Int).Div(new(big.Int).Mul(endPrice, totalSupply), WAD)
	mDiff := new(big.Int).Sub(mEnd, mStart)

	s1 := new(big.Int).Set(soldTokens)
	sAfter := new(big.Int).Sub(soldTokens, amountInOther)

	r1 := reserveAtWad(s1, sCurve, mStart, mDiff, totalSupply)
	rAfter := reserveAtWad(sAfter, sCurve, mStart, mDiff, totalSupply)
	return new(big.Int).Sub(r1, rAfter)
}
