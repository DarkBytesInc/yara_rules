rule Win_Trojan_Spambot_93
{
strings:
	$a0 = { e483bf40976b389ffe5bf8e3061155af6200dc6b3cc4e111ffffafffa3d940229f71a1aff611f190b700ef6b284de1c345d1b80cb4167ff4ffffd0cedc06811f0388977e3a13009fca71a558a8049f93d313a740ffe3ffff1bdc78a5c6cf42646c241d4198cea40c044c9371fce2 }

condition:
	$a0
}

        
