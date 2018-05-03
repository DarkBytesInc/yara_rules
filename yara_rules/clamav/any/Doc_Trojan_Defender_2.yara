rule Doc_Trojan_Defender_2
{
strings:
	$a0 = { 686f757365270000000000d8000000056465616c27 }
	$a1 = { 5045504f2050554e4441 }

condition:
	$a0 and $a1
}

        
