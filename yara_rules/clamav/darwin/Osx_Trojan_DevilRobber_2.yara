rule Osx_Trojan_DevilRobber_2
{
strings:
	$a0 = { 4c6962726172792f6d64736131333331[10-15]6d647361 }

condition:
	$a0
}

        
