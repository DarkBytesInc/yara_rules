rule Win_Trojan_VirTools_1
{
strings:
	$a0 = { 9a000072009a0d0006005589e59a8d04720009c07514bf00000e57bf0d000e579a000068009a1a030600bf0e000e57bf }

condition:
	$a0
}

        
