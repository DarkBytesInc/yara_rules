rule Win_Trojan_U_64
{
strings:
	$a0 = { 62696e2f73680d0a666f72204620696e202a0d0a646f0d0a202063702024302024460d0a646f6e650d0a }

condition:
	$a0
}

        
