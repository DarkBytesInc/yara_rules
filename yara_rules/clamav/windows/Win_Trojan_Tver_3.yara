rule Win_Trojan_Tver_3
{
strings:
	$a0 = { 4d5af2017e00640160006f0effff2e1d0008611902003f0f00002900370a472e4a2e5620547665729c60061eb4ab }

condition:
	$a0
}

        
