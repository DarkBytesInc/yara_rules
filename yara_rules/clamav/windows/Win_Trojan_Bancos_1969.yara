rule Win_Trojan_Bancos_1969
{
strings:
	$a0 = { c77d362bf1c12ae475cb5f4d834953d842b12b26a51cad1b1ab070521ab51f2f6b736eae0f5d3a2d7ce8204f82c4bb063c11c1ce8d635e2b1aceb6cfa0b44d2db8f8d723da3dcc7ba8f7762d79577a1ef6c4efaaeff3458064 }

condition:
	$a0
}

        
