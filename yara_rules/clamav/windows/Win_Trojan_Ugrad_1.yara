rule Win_Trojan_Ugrad_1
{
strings:
	$a0 = { 83ee472effb41d002effb41f005650060e1fc6842100008cc001840e0080bc000000750e8b840100a300018a840300 }

condition:
	$a0
}

        
