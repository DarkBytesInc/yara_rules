rule Win_Spyware_Banker_3455
{
strings:
	$a0 = { 9840e887bb2cbd8b60078e922910742ada477f16653a77f2e0fd0f0cb4d11545f8fa86f8d8dbb10d6f1387384c4090cec5c08b7ab3f0b7d1d1934696ed2c4cdf7c896f849b558d4140d7416aac10245e }

condition:
	$a0
}

        
