rule Win_Trojan_W_337
{
strings:
	$a0 = { f7e18038010f849802000068e006000090cd200d0040005985c00f84830200009757e8 }

condition:
	$a0
}

        
