rule Win_Trojan_Wit_10
{
strings:
	$a0 = { 4303a34503a14703a36a03fe067703803e770333745833c08ec026a19200268b1e9000a373 }

condition:
	$a0
}

        
