rule Win_Trojan_Dropper_73
{
strings:
	$a0 = { 6d6964286f70312c6f70322c6f703329656e6466756e6374696f6e63303d223464356139 }

condition:
	$a0
}

        
