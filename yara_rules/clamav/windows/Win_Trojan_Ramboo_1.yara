rule Win_Trojan_Ramboo_1
{
strings:
	$a0 = { 67005253ad001300504552534f4e414c2e584c532152414d424f4f002000ca00280080026b }

condition:
	$a0
}

        
