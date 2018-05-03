rule Unix_Trojan_MSShellcode_35
{
strings:
	$a0 = { 7ffffa783ba001ff3b9dfe023b7dfe0397e1fffc9781fffc9761fffc7c240b78387dfe02381dfe6744ffff027c7a1b783b3dfe113ee00a0762f74dba3ac0115c }

condition:
	$a0
}

        
