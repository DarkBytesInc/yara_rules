rule Win_Trojan_Companion_26
{
strings:
	$a0 = { 31019a0000bc005589e581ec0001b01b50b87208ba000052509a1b011e01b02350b87208ba000052509a1b011e }

condition:
	$a0
}

        
