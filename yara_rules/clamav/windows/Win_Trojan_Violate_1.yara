rule Win_Trojan_Violate_1
{
strings:
	$a0 = { 56696f2d4c6974652c205441412c20566972756c656e742047726166666974692c }

condition:
	$a0
}

        
