rule Win_Trojan_Kaczor_8
{
strings:
	$a0 = { 2ec006????042eff06????[0-1]2e813e????541175eb }

condition:
	$a0
}

        
