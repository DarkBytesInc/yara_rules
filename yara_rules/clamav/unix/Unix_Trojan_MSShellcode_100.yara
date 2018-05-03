rule Unix_Trojan_MSShellcode_100
{
strings:
	$a0 = { 7ffffa783ba001ff97e1fffc7c3c0b783b7dfe119761fffc7c3a0b789741fffc9781fffc97e1fffc3bff01ff3bfffe02382101ff3821fe0597e1fffc7c240b78 }

condition:
	$a0
}

        
