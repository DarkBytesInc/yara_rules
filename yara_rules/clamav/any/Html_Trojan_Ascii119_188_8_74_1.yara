rule Html_Trojan_Ascii119_188_8_74_1
{
strings:
	$a0 = { 3131392e3138382e382e3734 }

condition:
	$a0
}

        
