rule Html_Trojan_Ascii31_170_165_249_1
{
strings:
	$a0 = { 33312e3137302e3136352e323439 }

condition:
	$a0
}

        
