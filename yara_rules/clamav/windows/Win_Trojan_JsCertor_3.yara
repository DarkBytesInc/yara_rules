rule Win_Trojan_JsCertor_3
{
strings:
	$a0 = { 433a5c444f43554d457e315c617a617a61[0-200]6576616c2866756e6374696f6e28702c612c632c6b2c652c64297b }

condition:
	$a0
}

        
