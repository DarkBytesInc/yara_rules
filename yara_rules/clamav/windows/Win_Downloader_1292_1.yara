rule Win_Downloader_1292_1
{
strings:
	$a0 = { b65aca2e3745788ab56b1f32a56ce23868748e703a2f2c7a3a69312d73ca2e6e2e1f8cfbb963d5dbf07068e54e20843166b85a7eefebb378dd1f0ae409482a579032eb2133d64234ad0acc4301ebefffe43e01befffe4601aababb60000000 }

condition:
	$a0
}

        
