rule Win_Trojan_Trojan_113
{
strings:
	$a0 = { 6f20b8023d32f6b282cd218bd8b43fba2c01b92603cd21b8023d32f6b28acd218bd8b440ba2c01b92603cd21cd203e746d702e636f6d0d0a746d702e636f6d20746d702e66 }

condition:
	$a0
}

        
