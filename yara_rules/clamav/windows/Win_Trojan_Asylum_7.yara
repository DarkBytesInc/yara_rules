rule Win_Trojan_Asylum_7
{
strings:
	$a0 = { 680e324000e800000ce483f80175166a0168d431400068ad3140006802000080e800000a7f }

condition:
	$a0
}

        
