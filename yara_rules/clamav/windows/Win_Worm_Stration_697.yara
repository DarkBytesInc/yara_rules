rule Win_Worm_Stration_697
{
strings:
	$a0 = { 635c496e7465726e6574205365637572697479007b43454633303743392d454132332d346264642d413836442d4541313334414345323730447d00004f7574706f73744669726577616c6c00534f4654574152455c41676e6974756d5c4f7574706f7374204669726577616c6c0000006b6176737663000000000000534f4654574152455c4b6173 }

condition:
	$a0
}

        