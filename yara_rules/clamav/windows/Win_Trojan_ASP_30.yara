rule Win_Trojan_ASP_30
{
strings:
	$a0 = { 27bda8c1a27368656c6cb6d4cff3[0-25]2e6974656d732e6974656d28737a636d6436292e696e766f6b6576657262 }

condition:
	$a0
}

        
