rule Win_Trojan_N_7
{
strings:
	$a0 = { e80000cc5d81ed0300e800001e06e8ef01b88863cd2181fb4c557455b44abbffffcd2183eb23b44acd21b448bb2200cd21723e488ec026c60600005a26c70601000800 }

condition:
	$a0
}

        
