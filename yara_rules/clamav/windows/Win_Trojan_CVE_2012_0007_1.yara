rule Win_Trojan_CVE_2012_0007_1
{
strings:
	$a0 = { 7374796c653d[0-50]5c2c22[0-50]65787072657373696f6e }

condition:
	$a0
}

        
