rule Win_Trojan_BAT_102
{
strings:
	$a0 = { 2e7368656c6c2229203e3e202577696e646972255c6b6579735f7265672e766273 }

condition:
	$a0
}

        
