rule Win_Downloader_Banload_680
{
strings:
	$a0 = { a9b86a6110d927bf0583c8404f5334d17d69b044aa0634532de7c4dadd3875a344c1caccf1d85de21cacb112dab8425baee18e9ee1270b11a5aad666dc0bd03a7f7b093410ce8db319e6d6a90e682e859d143d2c754710a1dc1af7df7669df0764ce0fed740c6f6f9cac969af7e79242e6b02c10af2d }

condition:
	$a0
}

        
