rule Win_Downloader_1270_1
{
strings:
	$a0 = { 4f715c1cc6ffc0464cb550fd296e865e95e18f314d9ca90d871fa996f3c2c65fb4d5fadfc24d4731e00263891f15df5351eeea1e27e0794141b4b3b342cef7fdde3c3834ba73fc22629f909a5b3d6ba3cfef6287b3fa882f95bf }

condition:
	$a0
}

        
