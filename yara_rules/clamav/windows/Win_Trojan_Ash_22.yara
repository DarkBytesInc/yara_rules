rule Win_Trojan_Ash_22
{
strings:
	$a0 = { 40b904008d960301cd21b440b9e3028d960701cd21b8004233c933d2cd218b8618044089860401 }

condition:
	$a0
}

        
