rule Win_Trojan_VBS_203
{
strings:
	$a0 = { 7368656c6c25323225336225 }
	$a1 = { 25323025323261646f646225323225 }
	$a2 = { 32616d65726963616e61732e636f6d2532 }

condition:
	$a0 and $a1 and $a2
}

        
