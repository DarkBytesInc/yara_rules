rule Win_Trojan_MAD_8
{
strings:
	$a0 = { fdfc7337ddabee5af0c6ffefcc5f97e9f096eeef996fefa200c63be9a2f0c7efef326ec20bee3a2b2332edf598efdf05adecb0d4c097efdf65af20d40d6f12a45bf02cc8dca2f005669587eee5f40566859bee97ee0a9984eeeec9a20ed97337e2efee3f }

condition:
	$a0
}

        
