rule Doc_Trojan_NiceDay_4
{
strings:
	$a0 = { 4d7367426f782022b9a7bad8c4e3b4f0b6d4c1cb2cb0b4c8b7b6a8becdb8e6cbdfc4e3cfebd6aab5c0b5c42e2e2e2e222c2022cca8cde5204e4f2e31204d6163726f20566972757322 }

condition:
	$a0
}

        
