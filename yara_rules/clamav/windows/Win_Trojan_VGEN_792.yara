rule Win_Trojan_VGEN_792
{
strings:
	$a0 = { 9a00008c009a00002a005589e59ac2012a00bf52011e57bf00000e5731c0509a71068c009ac8058c009a0e028c00b007 }

condition:
	$a0
}

        
