rule Win_Downloader_63713_1
{
strings:
	$a0 = { e917000000e2de8dee00000000b30000af8600009bf412e600f50000c1c21253f7d7ff150c21400089 }

condition:
	$a0
}

        
