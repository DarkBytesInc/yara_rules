rule Win_Trojan_Mun_1
{
strings:
	$a0 = { 01010055e60500000001000103000063000000070000006403 }

condition:
	$a0
}

        
