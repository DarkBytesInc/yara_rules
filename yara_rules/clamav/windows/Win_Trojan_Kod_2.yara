rule Win_Trojan_Kod_2
{
strings:
	$a0 = { 6a108d55f089d0508b8548c5ffff50e813fdffff83c40c89c083f8ff752668d08b0408e82ffcffff83c4048b8548c5ffff50e810fcffff83c4046a01e8a6fcffff }
	$a1 = { 66792061207461726765742e0a002d70002d7400657272 }

condition:
	$a0 and $a1
}

        
