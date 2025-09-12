// SPDX-License-Identifier: ice License 1.0

package coingecko

// ([a-z1-9\-]+).svg
// replace to
//
//	"$1": &Coin{
//			IconUrl: "https://cdn.ice.io/online+/assets/coins/$1.svg",
//		},
//
// and to (for upd sql)
// WHEN symbol = '$1' THEN 'https://cdn.ice.io/online+/assets/coins/$1.svg'
var coinOverwrites = map[string]*Coin{
	"binance-bridged-usdt-bnb-smart-chain": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdt.svg",
		Name:    "Bridged USDT",
	},
	"bridged-usdt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdt.svg",
		Name:    "Bridged USDT",
	},

	"ion": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ion.svg",
	},
	"ice": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ion.svg",
	},

	"spx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/spx.svg",
	},
	"mina": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mina.svg",
	},
	"buidl": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/buidl.svg",
	},
	"oxb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/oxb.svg",
	},
	"kas": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kas.svg",
	},
	"usdc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdc.svg",
	},
	"usdt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usdt.svg",
	},
	"theta": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/theta.svg",
	},
	"purr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/purr.svg",
	},
	"ldo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ldo.svg",
	},
	"xtz": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xtz.svg",
	},
	"weeth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/weeth.svg",
	},
	"pi": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pi.svg",
	},
	"snow": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/snow.svg",
	},
	"glm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/glm.svg",
	},
	"inj": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/inj.svg",
	},
	"1inch": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/1inch.svg",
	},
	"eth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eth.svg",
	},
	"strk": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/strk.svg",
	},
	"fet": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fet.svg",
	},
	"gt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/gt.svg",
	},
	"usde": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usde.svg",
	},
	"neo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/neo.svg",
	},
	"usds": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usds.svg",
	},
	"prime": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/prime.svg",
	},
	"sei": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sei.svg",
	},
	"super": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/super.svg",
	},
	"xlm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xlm.svg",
	},
	"avax": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/avax.svg",
	},
	"ton": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ton.svg",
	},
	"toncoin": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ton.svg",
		Name:    "Toncoin",
	},
	"leo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/leo.svg",
	},
	"ena": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ena.svg",
	},
	"hype": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/hype.svg",
	},
	"algo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/algo.svg",
	},
	"usd1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usd1.svg",
	},
	"eos": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eos.svg",
	},
	"steth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/steth.svg",
	},
	"eigen": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eigen.svg",
	},
	"cro": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/cro.svg",
	},
	"dot": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dot.svg",
	},
	"nexo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/nexo.svg",
	},
	"ape": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ape.svg",
	},
	"wbtc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wbtc.svg",
	},
	"rune-1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/rune-1.svg",
	},
	"fdusd": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fdusd.svg",
	},
	"pepe": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pepe.svg",
	},
	"link": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/link.svg",
	},
	"fantom": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fantom.svg",
	},
	"dai": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dai.svg",
	},
	"ada": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ada.svg",
	},
	"eos-1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/eos-1.svg",
	},
	"stg": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/stg.svg",
	},
	"zk": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zk.svg",
	},
	"bnb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bnb.svg",
	},
	"arkm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/arkm.svg",
	},
	"cbbtc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/cbbtc.svg",
	},
	"gala": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/gala.svg",
	},
	"fartcoin": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fartcoin.svg",
	},
	"dogs": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dogs.svg",
	},
	"ltc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ltc.svg",
	},
	"doge": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/doge.svg",
	},
	"pyth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pyth.svg",
	},
	"wld": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wld.svg",
	},
	"susde": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/susde.svg",
	},
	"matic": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/matic.svg",
	},
	"sol": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sol.svg",
	},
	"zro": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zro.svg",
	},
	"apt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/apt.svg",
	},
	"neiro": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/neiro.svg",
	},
	"mkr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mkr.svg",
	},
	"zec": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zec.svg",
	},
	"jup": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/jup.svg",
	},
	"brett": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/brett.svg",
	},
	"cfx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/cfx.svg",
	},
	"uni": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/uni.svg",
	},
	"dash": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dash.svg",
	},
	"egld": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/egld.svg",
	},
	"om": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/om.svg",
	},
	"usds-1": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/usds-1.svg",
	},
	"shib": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/shib.svg",
	},
	"sui": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sui.svg",
	},
	"rune": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/rune.svg",
	},
	"hnt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/hnt.svg",
	},
	"mew": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mew.svg",
	},
	"tia": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/tia.svg",
	},
	"grt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/grt.svg",
	},
	"xrp": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xrp.svg",
	},
	"trump": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/trump.svg",
	},
	"near": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/near.svg",
	},
	"flr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/flr.svg",
	},
	"vet": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/vet.svg",
	},
	"pengu": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pengu.svg",
	},
	"core": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/core.svg",
	},
	"not": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/not.svg",
	},
	"flow": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/flow.svg",
	},
	"s": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/s.svg",
	},
	"stx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/stx.svg",
	},
	"moodeng": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/moodeng.svg",
	},
	"w": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/w.svg",
	},
	"sand": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/sand.svg",
	},
	"arb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/arb.svg",
	},
	"tkx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/tkx.svg",
	},
	"hbar": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/hbar.svg",
	},
	"iota": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/iota.svg",
	},
	"ksm": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ksm.svg",
	},
	"panecakeswap": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/panecakeswap.svg",
	},
	"wbt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wbt.svg",
	},
	"bch": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bch.svg",
	},
	"floki": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/floki.svg",
	},
	"op": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/op.svg",
	},
	"render": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/render.svg",
	},
	"pendle": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/pendle.svg",
	},
	"jitosol": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/jitosol.svg",
	},
	"akt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/akt.svg",
	},
	"btc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/btc.svg",
	},
	"btt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/btt.svg",
	},
	"zeta": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/zeta.svg",
	},
	"ordi": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ordi.svg",
	},
	"kava": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kava.svg",
	},
	"ogy": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ogy.svg",
	},
	"trx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/trx.svg",
	},
	"popcat": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/popcat.svg",
	},
	"etc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/etc.svg",
	},
	"icp": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/icp.svg",
	},
	"mana": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mana.svg",
	},
	"aioz": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/aioz.svg",
	},
	"ray": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ray.svg",
	},
	"kcs": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kcs.svg",
	},
	"jamsy": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/jamsy.svg",
	},
	"base": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/base.svg",
	},
	"dydx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/dydx.svg",
	},
	"imx": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/imx.svg",
	},
	"aave": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/aave.svg",
	},
	"xmr": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/xmr.svg",
	},
	"paxg": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/paxg.svg",
	},
	"virtual": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/virtual.svg",
	},
	"tao": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/tao.svg",
	},
	"bgb": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bgb.svg",
	},
	"lbtc": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/lbtc.svg",
	},
	"wif": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/wif.svg",
	},
	"ondo": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ondo.svg",
	},
	"bera": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bera.svg",
	},
	"weth": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/weth.svg",
		Name:    "WETH",
	},
	"atom": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/atom.svg",
	},
	"giga": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/giga.svg",
	},
	"mnt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/mnt.svg",
	},
	"fil": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/fil.svg",
	},
	"twt": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/twt.svg",
	},
	"grass": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/grass.svg",
	},
	"kaia": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/kaia.svg",
	},
	"bsc-usd": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/bsc-usd.svg",
	},
	"morpho": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/morpho.svg",
	},
	"ai16z": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/ai16z.svg",
	},
	"launchcoin": &Coin{
		IconUrl: "https://cdn.ice.io/online+/assets/coins/launchcoin.svg",
	},
}
