rule Win_Trojan_Diablo_4
{
strings:
	$a0 = { 0100424014010000ae0420004a0028008a004f4eae0420004a0028009400010024004a010000240054010100a3001f00200060010f001d00a30001000b001900050093004500ae0420006a01280074016600e0009a0080006b }

condition:
	$a0
}

        