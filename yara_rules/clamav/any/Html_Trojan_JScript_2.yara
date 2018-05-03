rule Html_Trojan_JScript_2
{
strings:
	$a0 = { 736372697074206c616e67756167653d6a6176617363726970743e66756e6374696f6e }
	$a1 = { 626e623235287a29 }

condition:
	$a0 and $a1
}

        
