rule Osx_Trojan_Imuler_3
{
strings:
	$a0 = { 20687474702075706c6f6164[0-210]2a2a75706c6f61642e657865202d66[0-29]786e7461736b7a }

condition:
	$a0
}

        
