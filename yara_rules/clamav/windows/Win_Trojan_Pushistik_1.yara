rule Win_Trojan_Pushistik_1
{
strings:
	$a0 = { 20696e20282a2e6261742920646f2063616c6c2025302050555348495354494b20252566 }

condition:
	$a0
}

        
