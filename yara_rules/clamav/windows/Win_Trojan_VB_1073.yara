rule Win_Trojan_VB_1073
{
strings:
	$a0 = { 68c83f4000e8f0ffffff000000000000300000004000000000000000b25bb375fe9c914e81634a91 }

condition:
	$a0
}

        
