rule Win_Trojan_Dialer_26
{
strings:
	$a0 = { 4449414c584c4954452e4469616c584c6974654374726c2e3100000000000000ae177df537cec84bb232 }

condition:
	$a0
}

        
