rule Win_Trojan_LdPinch_73
{
strings:
	$a0 = { e8310100006a006a006a046a006a0368000000c0680c390010e8fa0000008945fc400f8486000000 }

condition:
	$a0
}

        
