rule Win_Downloader_Zlob_1479
{
strings:
	$a0 = { 67d5bade8e072ac5256d7c7ac49f80e90e0457a7d0fd16201cad22e02cf123456371252da223bceebd11cdb6666cda93d5b509e44f5d43f00f55ae185e90ce25b587033b34cc40fea93109824a7676fc2f7fcb2fbad27a3944cb419602b2f4ca4e607c }

condition:
	$a0
}

        
