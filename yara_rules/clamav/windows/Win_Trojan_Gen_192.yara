rule Win_Trojan_Gen_192
{
strings:
	$a0 = { 50b8722250e8880f83c406e9a800b8542550b8782250e8b3175959b88722508b1e1025ff37 }

condition:
	$a0
}

        
