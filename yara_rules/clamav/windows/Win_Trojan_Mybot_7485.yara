rule Win_Trojan_Mybot_7485
{
strings:
	$a0 = { 16a20e0a2844ad359000dc14b5fcebb048558709fd4d2f7ea283284acf86885070b6d86526ab4d8673ef3927059af14153622ab1efec3596211900e4ec029b614abedc6524f8afd1f15b003a85d00a953b76068c89e78bb0f87d4f8a9b134ab3d06058b2bfd0c44fb866ea9388ba1469ed81e58dab942ffb0f2152bcf1244404 }

condition:
	$a0
}

        