rule Win_Trojan_Delwin_5
{
strings:
	$a0 = { 6d646972202f73202f7120433a5c50524f4752417e315c0d0a0d0a726d646972202f73202f7120 }

condition:
	$a0
}

        
