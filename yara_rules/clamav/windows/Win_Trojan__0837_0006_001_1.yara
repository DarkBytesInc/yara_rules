rule Win_Trojan__0837_0006_001_1
{
strings:
	$a0 = { 217210e87d00720bb91e058d160001b440cd212e8b1e52012e8b164a012e8b0e4c01b80157cd21 }

condition:
	$a0
}

        
