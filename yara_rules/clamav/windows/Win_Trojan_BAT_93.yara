rule Win_Trojan_BAT_93
{
strings:
	$a0 = { 72656e202577696e646972255c2a2e6f6378202a2e676179[0-13]5c2a2e696e69202a2e676179 }

condition:
	$a0
}

        
