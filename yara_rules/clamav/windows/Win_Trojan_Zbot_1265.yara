rule Win_Trojan_Zbot_1265
{
strings:
	$a0 = { 7400610073006b0068006f00730074002e }
	$a1 = { 504f535400000000474554[0-33]2e0074006d0070 }
	$a2 = { 687474703a2f2f004e5353 }

condition:
	$a0 and $a1 and $a2
}

        
