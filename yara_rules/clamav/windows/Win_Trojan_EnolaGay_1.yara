rule Win_Trojan_EnolaGay_1
{
strings:
	$a0 = { 50e834008cc005100001064c0001064400581f2e8e1644002e8b2646002eff2e4a00e81300fcb91400be3600bf0001 }

condition:
	$a0
}

        
