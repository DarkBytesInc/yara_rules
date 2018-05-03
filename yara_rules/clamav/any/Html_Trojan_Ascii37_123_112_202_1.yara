rule Html_Trojan_Ascii37_123_112_202_1
{
strings:
	$a0 = { 33372e3132332e3131322e323032 }

condition:
	$a0
}

        
