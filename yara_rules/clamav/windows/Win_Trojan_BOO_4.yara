rule Win_Trojan_BOO_4
{
strings:
	$a0 = { 0602060102eb0a90c70602060103eb019053b90400518a3609008a1626028b0e0a00a10206cd6d }

condition:
	$a0
}

        
