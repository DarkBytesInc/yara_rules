rule Win_Trojan_Betabot_1
{
strings:
	$a0 = { 6363303d2573266363313d25730000002663732568753d00266673683d00 }

condition:
	$a0
}

        
