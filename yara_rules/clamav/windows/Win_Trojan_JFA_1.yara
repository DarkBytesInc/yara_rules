rule Win_Trojan_JFA_1
{
strings:
	$a0 = { 81ee1b02eb0100bf380203fe8aa42202b905038a0532c4880547e2f7bf0001bb0000b904008a80e50488054743e2f6 }

condition:
	$a0
}

        
