rule Win_Trojan_Dialer_85
{
strings:
	$a0 = { 7a4061cf7dd0363f2d2a4e2e86ac0cedcb66b8a95253547344d8de36e0a992696b6d6d62481647b4a75ff885e43c7366fc68727153508d16cf6fac6120546f622612e47a }

condition:
	$a0
}

        
