rule Win_Trojan_Runner_3
{
strings:
	$a0 = { 6d31000d010500466f726d31001901004200220023ffffffff240500466f726d31002e00350000000000000000170700005703000044004603ff011b00000001050054657874320002047800e00127061d01120100ff031b00000002050054657874310002047800780027061d }

condition:
	$a0
}

        