rule Win_Trojan_Wup_1
{
strings:
	$a0 = { 6e657420757365202f64656c205c5c25315c69706324 }
	$a1 = { 707365786563205c5c2531202d75[0-66]2e657865 }

condition:
	$a0 and $a1
}

        
