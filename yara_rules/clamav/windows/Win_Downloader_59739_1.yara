rule Win_Downloader_59739_1
{
strings:
	$a0 = { 67e300517805b92f6e16089c0b0c24f7c1313a632b72149d7805b91f1d646a8b0c248d642404e801 }

condition:
	$a0
}

        
