rule Win_Trojan_CIH_1
{
strings:
	$a0 = { e8000000005b8d4b425150500f014c24fe5b83c31cfa8b2b668b6bfc8d711256668973fcc1ee10668973025ecc568bf08b48fcf3a483e8088b300bf67402ebf0 }

condition:
	$a0
}

        
