rule Win_Trojan_Bunter_1
{
strings:
	$a0 = { ba1201b861043b060200721bb409ba1801cd21cd2012345678901234567890123456789012 }

condition:
	$a0
}

        
