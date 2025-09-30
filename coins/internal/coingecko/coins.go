// SPDX-License-Identifier: ice License 1.0

package coingecko

// ([a-z1-9\-]+).svg
// replace to
//
//	"symbol:$1": &Coin{
//			IconUrl: "https://cdn.ice.io/online+/assets/coins/$1.svg",
//		},
//
// and to (for upd sql)
// WHEN symbol = '$1' THEN 'https://cdn.ice.io/online+/assets/coins/$1.svg'
var coinOverwrites = map[string]*Coin{
	"id:binance-bridged-usdt-bnb-smart-chain": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdt.svg",
		Name:    "Bridged USDT",
	},
	"id:bridged-usdt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdt.svg",
		Name:    "Bridged USDT",
	},

	"id:ion": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ion.svg",
	},
	"id:ice": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ion.svg",
	},

	"symbol:spx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/spx.svg",
	},
	"symbol:mina": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mina.svg",
	},
	"symbol:buidl": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/buidl.svg",
	},
	"symbol:oxb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/oxb.svg",
	},
	"symbol:kas": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kas.svg",
	},
	"symbol:usdc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdc.svg",
	},
	"symbol:usdt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdt.svg",
	},
	"symbol:theta": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/theta.svg",
	},
	"symbol:purr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/purr.svg",
	},
	"symbol:ldo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ldo.svg",
	},
	"symbol:xtz": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xtz.svg",
	},
	"symbol:weeth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/weeth.svg",
	},
	"symbol:pi": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pi.svg",
	},
	"symbol:snow": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/snow.svg",
	},
	"symbol:glm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/glm.svg",
	},
	"symbol:inj": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/inj.svg",
	},
	"symbol:1inch": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/1inch.svg",
	},
	"symbol:eth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eth.svg",
	},
	"symbol:strk": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/strk.svg",
	},
	"symbol:fet": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fet.svg",
	},
	"symbol:gt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/gt.svg",
	},
	"symbol:usde": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usde.svg",
	},
	"symbol:neo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/neo.svg",
	},
	"symbol:usds": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usds.svg",
	},
	"symbol:prime": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/prime.svg",
	},
	"symbol:sei": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sei.svg",
	},
	"symbol:super": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/super.svg",
	},
	"symbol:xlm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xlm.svg",
	},
	"symbol:avax": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/avax.svg",
	},
	"symbol:ton": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ton.svg",
	},
	"symbol:toncoin": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ton.svg",
		Name:    "Toncoin",
	},
	"symbol:leo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/leo.svg",
	},
	"symbol:ena": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ena.svg",
	},
	"symbol:hype": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/hype.svg",
	},
	"symbol:algo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/algo.svg",
	},
	"symbol:usd1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usd1.svg",
	},
	"symbol:eos": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eos.svg",
	},
	"symbol:steth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/steth.svg",
	},
	"symbol:eigen": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eigen.svg",
	},
	"symbol:cro": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/cro.svg",
	},
	"symbol:dot": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dot.svg",
	},
	"symbol:nexo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/nexo.svg",
	},
	"symbol:ape": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ape.svg",
	},
	"symbol:wbtc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wbtc.svg",
	},
	"symbol:rune-1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/rune-1.svg",
	},
	"symbol:fdusd": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fdusd.svg",
	},
	"symbol:pepe": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pepe.svg",
	},
	"symbol:link": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/link.svg",
	},
	"symbol:fantom": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fantom.svg",
	},
	"symbol:dai": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dai.svg",
	},
	"symbol:ada": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ada.svg",
	},
	"symbol:eos-1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eos-1.svg",
	},
	"symbol:stg": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/stg.svg",
	},
	"symbol:zk": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zk.svg",
	},
	"symbol:bnb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bnb.svg",
	},
	"symbol:arkm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/arkm.svg",
	},
	"symbol:cbbtc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/cbbtc.svg",
	},
	"symbol:gala": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/gala.svg",
	},
	"symbol:fartcoin": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fartcoin.svg",
	},
	"symbol:dogs": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dogs.svg",
	},
	"symbol:ltc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ltc.svg",
	},
	"symbol:doge": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/doge.svg",
	},
	"symbol:pyth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pyth.svg",
	},
	"symbol:wld": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wld.svg",
	},
	"symbol:susde": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/susde.svg",
	},
	"symbol:matic": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/matic.svg",
	},
	"symbol:sol": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sol.svg",
	},
	"symbol:zro": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zro.svg",
	},
	"symbol:apt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/apt.svg",
	},
	"symbol:neiro": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/neiro.svg",
	},
	"symbol:mkr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mkr.svg",
	},
	"symbol:zec": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zec.svg",
	},
	"symbol:jup": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/jup.svg",
	},
	"symbol:brett": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/brett.svg",
	},
	"symbol:cfx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/cfx.svg",
	},
	"symbol:uni": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/uni.svg",
	},
	"symbol:dash": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dash.svg",
	},
	"symbol:egld": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/egld.svg",
	},
	"symbol:om": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/om.svg",
	},
	"symbol:usds-1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usds-1.svg",
	},
	"symbol:shib": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/shib.svg",
	},
	"symbol:sui": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sui.svg",
	},
	"symbol:rune": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/rune.svg",
	},
	"symbol:hnt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/hnt.svg",
	},
	"symbol:mew": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mew.svg",
	},
	"symbol:tia": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/tia.svg",
	},
	"symbol:grt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/grt.svg",
	},
	"symbol:xrp": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xrp.svg",
	},
	"symbol:trump": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/trump.svg",
	},
	"symbol:near": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/near.svg",
	},
	"symbol:flr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/flr.svg",
	},
	"symbol:vet": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/vet.svg",
	},
	"symbol:pengu": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pengu.svg",
	},
	"symbol:core": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/core.svg",
	},
	"symbol:not": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/not.svg",
	},
	"symbol:flow": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/flow.svg",
	},
	"symbol:s": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/s.svg",
	},
	"symbol:stx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/stx.svg",
	},
	"symbol:moodeng": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/moodeng.svg",
	},
	"symbol:w": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/w.svg",
	},
	"symbol:sand": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sand.svg",
	},
	"symbol:arb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/arb.svg",
	},
	"symbol:tkx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/tkx.svg",
	},
	"symbol:hbar": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/hbar.svg",
	},
	"symbol:iota": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/iota.svg",
	},
	"symbol:ksm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ksm.svg",
	},
	"symbol:panecakeswap": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/panecakeswap.svg",
	},
	"symbol:wbt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wbt.svg",
	},
	"symbol:bch": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bch.svg",
	},
	"symbol:floki": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/floki.svg",
	},
	"symbol:op": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/op.svg",
	},
	"symbol:render": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/render.svg",
	},
	"symbol:pendle": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pendle.svg",
	},
	"symbol:jitosol": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/jitosol.svg",
	},
	"symbol:akt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/akt.svg",
	},
	"symbol:btc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/btc.svg",
	},
	"symbol:btt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/btt.svg",
	},
	"symbol:zeta": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zeta.svg",
	},
	"symbol:ordi": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ordi.svg",
	},
	"symbol:kava": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kava.svg",
	},
	"symbol:ogy": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ogy.svg",
	},
	"symbol:trx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/trx.svg",
	},
	"symbol:popcat": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/popcat.svg",
	},
	"symbol:etc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/etc.svg",
	},
	"symbol:icp": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/icp.svg",
	},
	"symbol:mana": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mana.svg",
	},
	"symbol:aioz": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/aioz.svg",
	},
	"symbol:ray": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ray.svg",
	},
	"symbol:kcs": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kcs.svg",
	},
	"symbol:jamsy": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/jamsy.svg",
	},
	"symbol:base": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/base.svg",
	},
	"symbol:dydx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dydx.svg",
	},
	"symbol:imx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/imx.svg",
	},
	"symbol:aave": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/aave.svg",
	},
	"symbol:xmr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xmr.svg",
	},
	"symbol:paxg": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/paxg.svg",
	},
	"symbol:virtual": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/virtual.svg",
	},
	"symbol:tao": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/tao.svg",
	},
	"symbol:bgb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bgb.svg",
	},
	"symbol:lbtc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/lbtc.svg",
	},
	"symbol:wif": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wif.svg",
	},
	"symbol:ondo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ondo.svg",
	},
	"symbol:bera": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bera.svg",
	},
	"symbol:weth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/weth.svg",
		Name:    "WETH",
	},
	"symbol:atom": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/atom.svg",
	},
	"symbol:giga": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/giga.svg",
	},
	"symbol:mnt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mnt.svg",
	},
	"symbol:fil": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fil.svg",
	},
	"symbol:twt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/twt.svg",
	},
	"symbol:grass": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/grass.svg",
	},
	"symbol:kaia": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kaia.svg",
	},
	"symbol:bsc-usd": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bsc-usd.svg",
	},
	"symbol:morpho": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/morpho.svg",
	},
	"symbol:ai16z": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ai16z.svg",
	},
	"symbol:launchcoin": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/launchcoin.svg",
	},
}
