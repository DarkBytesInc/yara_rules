rule Win_Trojan_Remor_7
{
strings:
	$a0 = { 4003a34203a14403a36703fe067403803e740333745833c08ec026a19200268b1e9000a370 }

condition:
	$a0
}

        
