rule Win_Trojan_Deicide_13
{
strings:
	$a0 = { ba0001b94809cd21b457b0015a59cd21b43ecd218b1e }

condition:
	$a0
}

        
