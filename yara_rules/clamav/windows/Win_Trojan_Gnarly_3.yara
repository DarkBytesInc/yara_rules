rule Win_Trojan_Gnarly_3
{
strings:
	$a0 = { 2100640065006c00650074006500660069006c0065 }
	$a1 = { 210064006f0077006e006c006f00610064 }

condition:
	$a0 and $a1
}

        
