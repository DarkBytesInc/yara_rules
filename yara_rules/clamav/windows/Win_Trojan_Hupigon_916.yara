rule Win_Trojan_Hupigon_916
{
strings:
	$a0 = { 7ff3deda710771dc942bac29f27cf979b0b5b06e1d7a91e3d5b488fd524f0f21232de460fb5d8aeca9c1ab4e88967b1498f37323c8f1b147af8fe79fce7be26f3988a1161dc3991439cf3e5bb4ace59a1f7d1cbadbd18e054abd00ec6be7b50f4038e0ba5748b1ddfb73e1da5087 }

condition:
	$a0
}

        
