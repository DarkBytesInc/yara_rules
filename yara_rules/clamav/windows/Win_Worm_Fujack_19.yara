rule Win_Worm_Fujack_19
{
strings:
	$a0 = { 3c696672616d65207372633d22687474703a2f2f7777772e353164 }

condition:
	$a0
}

        
