rule Win_Trojan_Spambot_194
{
strings:
	$a0 = { ffffffff01c0d0e20bfa0ba186fec3acf394bccd9429f6c0998f7a7936a4d6752758c6ffff6e02b61c2a6b78bad0586d4b7516a5433002ffff87ffa7f7b34b9ede784383e76c61572e90d8140d5978d4ffb81413ffffffff16aca919b054bca1805d819ab12a3e3eb8a45a71116f }

condition:
	$a0
}

        
