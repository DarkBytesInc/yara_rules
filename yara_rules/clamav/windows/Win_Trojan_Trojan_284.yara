rule Win_Trojan_Trojan_284
{
strings:
	$a0 = { 9a00000a005589e5c6063e0002c7064200e80331c0a34400b02650bf3e001e579a0b00030089ec5d31c09ad8000a0000 }

condition:
	$a0
}

        
