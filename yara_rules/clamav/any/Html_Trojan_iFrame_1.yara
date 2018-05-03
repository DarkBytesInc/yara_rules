rule Html_Trojan_iFrame_1
{
strings:
	$a0 = { 2e737263c2a03dc2a027687474703a2f2f667261756b65736172742e64652f636e742e70687027 }

condition:
	$a0
}

        
