rule Win_Trojan_Bytesv_2
{
strings:
	$a0 = { 01000000e55d81ed07104000b800000000be2810400003f5b95d010000310646464646e2f8 }

condition:
	$a0
}

        
