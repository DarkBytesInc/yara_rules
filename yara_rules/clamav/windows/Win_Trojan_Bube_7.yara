rule Win_Trojan_Bube_7
{
strings:
	$a0 = { 24040000ffd0e9aefeffff4b4f504f424100424f504f48410057696e646f777320496e7465726e657400687474703a2f2f }

condition:
	$a0
}

        
