rule Win_Trojan_Bancos_1046
{
strings:
	$a0 = { 90f2a68c2740eb05ae059e83544dcf1462968d329c220d53c29aabebf0f2174b0a46bb853b8cd313f28fe4b4dfee8ae620d0242f5eb7f426705db0c25d6718b3a37ac1c35ac952f43b0f954a5308209217596fd7e3faaf7e }

condition:
	$a0
}

        
