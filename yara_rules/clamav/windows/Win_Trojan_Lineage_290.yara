rule Win_Trojan_Lineage_290
{
strings:
	$a0 = { 4e0677ee1aab9c82156307f82649b61b7db5b82d73d94bb25a94baba4581cb3122331beedc9c0f7ae4fe5dac28d51a1815aac72d5ead615f195b4ec3c05f8b3a59d4deb47b298e334c0d69ccc99a32b98012686f59e4380142c8a411 }

condition:
	$a0
}

        
