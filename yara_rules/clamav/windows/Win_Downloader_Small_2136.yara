rule Win_Downloader_Small_2136
{
strings:
	$a0 = { ffd68bd88b433c8b44185068641114138945f4ffd6684811141368381114138945ecffd68b358410141350ffd6 }

condition:
	$a0
}

        
