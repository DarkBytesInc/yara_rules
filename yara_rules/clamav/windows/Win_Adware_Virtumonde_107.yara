rule Win_Adware_Virtumonde_107
{
strings:
	$a0 = { e3ebdf563524bb37f43457bbdbf962068fbe46f82bce3dab5c52de1050c41f6525463385567501979b13957f40240ce85f6993591f0aa8795110be483b22f3534aab21910cceb35d3aa3eabc41ef5d6b85107a67f6f8460070be2affb0867fc96fc70f349d4e68ca7efa626a2275a91b287d3baf64fd522df9c099634bc1ddbd7aa9487706fe6b45869e8eb6 }

condition:
	$a0
}

        