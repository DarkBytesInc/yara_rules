rule Win_Trojan_Peed_406
{
strings:
	$a0 = { 682225ff0089d083c404e99e00000068901500005981c14011000081c1901500 }

condition:
	$a0
}

        
