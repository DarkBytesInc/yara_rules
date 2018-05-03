rule Html_Trojan_Ascii212_44_64_202_1
{
strings:
	$a0 = { 3231322e34342e36342e323032 }

condition:
	$a0
}

        
