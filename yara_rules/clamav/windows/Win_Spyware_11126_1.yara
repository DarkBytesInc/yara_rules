rule Win_Spyware_11126_1
{
strings:
	$a0 = { 8b55008bc68b0be834e6ffff83c60483c3044f75eb8b5500a1f0404000b914334000e819e6ffff8b5500a1ec404000b928334000e807e6ffff8b5500a124414000b944334000e8f5e5ffff8b5500a128414000b958334000e8e3e5ffff5d5f5e5bc3 }

condition:
	$a0
}

        