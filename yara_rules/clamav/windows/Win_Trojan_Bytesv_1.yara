rule Win_Trojan_Bytesv_1
{
strings:
	$a0 = { 01000000e55d81ed07104000b84058b63cbe2810400003f5b951010000310646464646e2f8 }

condition:
	$a0
}

        
