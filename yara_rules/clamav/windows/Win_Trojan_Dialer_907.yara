rule Win_Trojan_Dialer_907
{
strings:
	$a0 = { 350000383939303230313230000000534538393900000069745f646d5f7365785f30310000000045 }

condition:
	$a0
}

        