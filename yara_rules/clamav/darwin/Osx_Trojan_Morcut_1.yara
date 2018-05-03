rule Osx_Trojan_Morcut_1
{
strings:
	$a0 = { 617474616368546f4d656d6f7279526567696f6e }
	$a1 = { 616d4953616e64626f786564 }
	$a2 = { 6d416d495072697655736572 }

condition:
	$a0 and $a1 and $a2
}

        
