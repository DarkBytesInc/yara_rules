rule Win_Trojan_Vgen_36
{
strings:
	$a0 = { 484f204f46460d0a52454d20d7e9860080fc40756f9c5053515256571e060e078bf28d0e9401515ffcb90500f3 }

condition:
	$a0
}

        
