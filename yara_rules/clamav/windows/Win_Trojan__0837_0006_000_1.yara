rule Win_Trojan__0837_0006_000_1
{
strings:
	$a0 = { 166e01e88000721db91c008d165a01b440cd217210e87d00720bb91e058d160001b440cd212e8b }

condition:
	$a0
}

        
