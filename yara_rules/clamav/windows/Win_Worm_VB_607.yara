rule Win_Worm_VB_607
{
strings:
	$a0 = { 72007400750070005c0075006e006d0075006c005f00670061006400690073002e0065007800650000001600000061003a005c0064006100740061002e0065007800650000001600000062003a005c0064006100740061002e0065007800650000001600000066003a005c0064006100740061002e0065007800650000001600000067003a005c0064006100740061002e00650078006500000016 }

condition:
	$a0
}

        