rule Win_Trojan_Cumulus_1
{
strings:
	$a0 = { 1c019a000097005589e5b800019a7c021c0181ec0001c7064406020031c0a3420631c0a34006b00050bf40021e }

condition:
	$a0
}

        
