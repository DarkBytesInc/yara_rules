rule Html_Trojan_Shellcode_22
{
strings:
	$a0 = { e0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08de0b08d }

condition:
	$a0
}

        
