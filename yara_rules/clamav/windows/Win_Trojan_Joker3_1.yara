rule Win_Trojan_Joker3_1
{
strings:
	$a0 = { e800005d81ed03018d9e38028a2780fc597403e80701b42ccd213ad67402eb7ffec232f68bc2b20af6f23c0174263c0274283c03742a3c04742c3c05742e3c0674303c }

condition:
	$a0
}

        