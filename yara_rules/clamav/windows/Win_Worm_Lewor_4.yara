rule Win_Worm_Lewor_4
{
strings:
	$a0 = { 5b8be55dc3000000ffffffff260000006c7172733e2a296e77622860603634322a66696e2b6c687761776866702a626c736b28777c710000ffffffff08000000646f776e2e747874000000006f70656e00000000e887f6ffffe8e6fbffffe8a9fdffffc351c70424070000006a008d44240450e8d8e9ffff85c0741768889740006a006a }

condition:
	$a0
}

        