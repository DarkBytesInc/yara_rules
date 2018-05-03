rule Doc_Trojan_Appder_1
{
strings:
	$a0 = { 73544d6163726f24203d20734d6524202b20223a41707064657222 }

condition:
	$a0
}

        
