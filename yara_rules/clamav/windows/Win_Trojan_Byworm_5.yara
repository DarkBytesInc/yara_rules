rule Win_Trojan_Byworm_5
{
strings:
	$a0 = { e800005d81ed????be46018b863e07b9??022ef7122e31022ed10a2e01022eff022eff0a2e29022e30022ed1022e29022ef6122eff022e01022ed10a2e31022ed0024646e2cc }

condition:
	$a0
}

        
