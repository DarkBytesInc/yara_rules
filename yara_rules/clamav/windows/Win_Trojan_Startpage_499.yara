rule Win_Trojan_Startpage_499
{
strings:
	$a0 = { 5c6d61696e5d20[0-22]687474703a2f2f7777772e616c6c63796265727365617263682e636f6d2f69652f }

condition:
	$a0
}

        
