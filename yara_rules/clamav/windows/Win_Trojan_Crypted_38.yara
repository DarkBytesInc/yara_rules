rule Win_Trojan_Crypted_38
{
strings:
	$a0 = { 2e53746f6e6500000010000000[0-2]001b01000000[0-2]0000000000000000000000000040 }

condition:
	$a0
}

        
