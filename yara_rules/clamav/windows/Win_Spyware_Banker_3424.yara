rule Win_Spyware_Banker_3424
{
strings:
	$a0 = { 0e967a6f6a0bbf80c21adc8f3650d9023e967334059b9efee8b1979d84a76c5b49797df1fc3ac744675aa2425a706e48e680b1dd4d73adbd93296ac6c530aed84597963d587ac51286302b }

condition:
	$a0
}

        
