rule Win_Trojan_G2_7
{
strings:
	$a0 = { 5a21000200000002000010fffff0fffeff00000001f0ff1c00000000000000bb1001b9f9002e8137000083c302e2f6 }

condition:
	$a0
}

        
