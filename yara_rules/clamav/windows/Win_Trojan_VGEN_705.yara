rule Win_Trojan_VGEN_705
{
strings:
	$a0 = { b452cd21268e5ffe078cdbb0a334f98edb813e080054427503e93d01813e08004e457503e93201380600007407031e }

condition:
	$a0
}

        
