rule Win_Trojan_Hackarmy_4
{
strings:
	$a0 = { 7574316465a9066ccdda5b6b31bc90636573472cdd77f7830d0077656266a13634008d7306797f2bffff6e00505249564d5347004e4f54494345044b0055534552f9f65bfb004a4f494e1de054005155 }

condition:
	$a0
}

        