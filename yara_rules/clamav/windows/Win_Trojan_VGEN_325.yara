rule Win_Trojan_VGEN_325
{
strings:
	$a0 = { 010eb874b9cd213d8828741190902e8b1e010181c30301e84c00e8630336c7060001b44c36c6060201cd588ed8 }

condition:
	$a0
}

        
