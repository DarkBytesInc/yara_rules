rule Win_Trojan_Madismo_1
{
strings:
	$a0 = { 72696b657320416761696e219a0000e2009a000076005589e5b800019a7c02e20081ec0001c6 }

condition:
	$a0
}

        
