rule Win_Worm_Stration_505
{
strings:
	$a0 = { 7f4f00000000011d1d1949000000353e23383d33325600000000a884859f8e859fc6a78e858c9f83d1eb00000000200000001c6e70777d706b1c656a404a4d5c540a0b6557564d5c4958 }

condition:
	$a0
}

        