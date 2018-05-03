rule Unix_Trojan_MSShellcode_101
{
strings:
	$a0 = { 7ffffa783ba001ff3b9dfe023b7dfe0397e1fffc9781fffc9761fffc7c240b78387dfe02381dfe6744ffff027c7a1b783b3dfe113ee0ff0262f7115c97e1fffc }

condition:
	$a0
}

        
