rule Win_Trojan_Peed_314
{
strings:
	$a0 = { b80100000048e84e00000051b95802000089d781c190010000e81400000059b8 }

condition:
	$a0
}

        
