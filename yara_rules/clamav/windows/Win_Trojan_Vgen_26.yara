rule Win_Trojan_Vgen_26
{
strings:
	$a0 = { 5e35130283c60eb99c0431044646f1f8f83e6c3247196c3247196f33471945076b095e58c3ebdd05122d1f0b0c }

condition:
	$a0
}

        
