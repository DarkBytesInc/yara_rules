rule Win_Trojan_VB_566
{
strings:
	$a0 = { 55fd892cdbaf356ec1ac2d146300fe667947549a3ca62d33a7dad71e534d5e3b5e2da8e8f431df329f73c4d4826249bfcc3a90007163a5e2eaaaedf662623b088fb0e8189a2f37e8776d7db5a0355675cbeee9143545c849f16c06f97956b33fab430a68c707943800038838d598906e9f87066496bd2c9687df7e918c691f9bffd49a2156867d38a7c465ae1d86b06564827e39996d }

condition:
	$a0
}

        