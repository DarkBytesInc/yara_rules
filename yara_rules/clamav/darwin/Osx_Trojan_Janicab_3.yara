rule Osx_Trojan_Janicab_3
{
strings:
	$a0 = { 504b0304[0-128]2ee280ae[0-6]2e617070 }

condition:
	$a0
}

        
