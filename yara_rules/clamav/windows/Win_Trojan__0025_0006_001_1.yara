rule Win_Trojan__0025_0006_001_1
{
strings:
	$a0 = { 89440233c026894515b904008bd6b440cd21061f8f4515804d0640b43e9c0ee8d8fe804d0540 }

condition:
	$a0
}

        
