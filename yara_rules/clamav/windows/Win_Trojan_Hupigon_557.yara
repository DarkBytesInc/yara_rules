rule Win_Trojan_Hupigon_557
{
strings:
	$a0 = { 7251a8710b348c47cf6795b4feffe39ae778894f5541b027248c31e952d146022b0356904e474767b6a6079aba82d9ecfdf8fa840e1b607b44d8a7fb33f7bd4a391fe6fe21f90d1b90628d7bbe9ed34b8995de1f1e2306a6f654cb32e10acf21576a667f2c83132e90 }

condition:
	$a0
}

        