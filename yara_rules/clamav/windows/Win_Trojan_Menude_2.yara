rule Win_Trojan_Menude_2
{
strings:
	$a0 = { 7472616e73666572696e672c2e2e203e3e633a5c77696e646f77735c6d736261636b652e646c6c20636f7079202a2e2a }

condition:
	$a0
}

        
