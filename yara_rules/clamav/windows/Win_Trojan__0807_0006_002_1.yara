rule Win_Trojan__0807_0006_002_1
{
strings:
	$a0 = { fd77b33e89864802b440b904008d960401cd21b440b914018d960801cd21b8004233c933d2cd21 }

condition:
	$a0
}

        
