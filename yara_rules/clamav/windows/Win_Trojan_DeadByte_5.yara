rule Win_Trojan_DeadByte_5
{
strings:
	$a0 = { 20696e20282a2e6261742920646f2063616c6c20253020446561645f4279746520252566 }

condition:
	$a0
}

        
