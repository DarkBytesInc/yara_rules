rule Win_Trojan_DNSchanger_10
{
strings:
	$a0 = { 45a7dc1cd397db6b69c6d2f2fff6d5856eeb6a15f8db6d62428a64fbd4ba638c772f0712e11f00655b4e09fccd7e0e8b6012b44bf622b33c4c73baa5da43bdd279d6d94cefe6de3b55b7d7a2c387d0d5529a6f45c4aa68327efb61abe8cb66dc4b5e0242dd6e0535673f0cacf10f0bdb0402035692320421 }

condition:
	$a0
}

        
