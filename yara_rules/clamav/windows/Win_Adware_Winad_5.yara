rule Win_Adware_Winad_5
{
strings:
	$a0 = { 536f6674776172655c0000000057696e646f77732053796e63726f416400000000484b45595f4c4f43414c5f4d414348494e455c536f6674776172655c57696e616420436c69656e7400000000706172616d0000000000000000008224000000002e3f41565f636f }

condition:
	$a0
}

        