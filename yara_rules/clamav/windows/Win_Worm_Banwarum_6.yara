rule Win_Worm_Banwarum_6
{
strings:
	$a0 = { 63686567005c6d737a73726e33322e646c6c006a00682e657865686f676f6e6877696e6c89e75589e581ec3c010000c785 }

condition:
	$a0
}

        