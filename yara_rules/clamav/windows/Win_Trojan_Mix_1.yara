rule Win_Trojan_Mix_1
{
strings:
	$a0 = { 8bec508cc0051000894604c746020000061e53515657b800008ec026833e3c03695f5e595b1f07585db452e8 }

condition:
	$a0
}

        
