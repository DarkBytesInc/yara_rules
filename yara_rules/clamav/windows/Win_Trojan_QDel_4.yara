rule Win_Trojan_QDel_4
{
strings:
	$a0 = { 8e067d00268e06f2e233c033ff00000a0d00594f55204d555354204245205354555049442e }

condition:
	$a0
}

        
