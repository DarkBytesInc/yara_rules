rule Win_Trojan_Bancos_1362
{
strings:
	$a0 = { 7f6e3c50e532ff46517feaaf90b690ee30c33dd5141527cc579b6739dc4f80cca5b78d0e8e534959e470eeee825e7279ee2bd7c9a3fecebc5d9dd47e48eee73053651e75ed927f14b48ffbb0ea945c31bb27e42cddfe979344bef132bdcc1a8231037778fc82ec30 }

condition:
	$a0
}

        
