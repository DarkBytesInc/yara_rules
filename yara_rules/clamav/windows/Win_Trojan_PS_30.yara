rule Win_Trojan_PS_30
{
strings:
	$a0 = { 14b9c50081371d2583c302e2f7f5251d789cc80824a96290937d2184e83c9107a88b1119e83c9d3910d0041b7690 }

condition:
	$a0
}

        
