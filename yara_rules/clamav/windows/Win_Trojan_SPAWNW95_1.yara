rule Win_Trojan_SPAWNW95_1
{
strings:
	$a0 = { 400050b8b423400050e850010000e8b9000000be01204000b905000000f3a4e8c6000000b8 }

condition:
	$a0
}

        
