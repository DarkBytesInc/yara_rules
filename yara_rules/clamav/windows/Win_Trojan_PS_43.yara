rule Win_Trojan_PS_43
{
strings:
	$a0 = { be1800bd2f012e812c062846464d75f6ee280680333b06b3ee460ce0476cd349437b569c6fabe928ba7251f527abf17aba72d34978808956 }

condition:
	$a0
}

        
