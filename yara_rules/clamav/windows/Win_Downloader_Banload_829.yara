rule Win_Downloader_Banload_829
{
strings:
	$a0 = { 652680e6cc7adb8851289a7d6683d2dc9e08cc0106db13cde78a08a958efb735f79909f003e03edd6f3d2b239fc298aed575f0e918123dd6c38282414e143d55c1ec3d7d77eb0353b308e529c1e56b9cadf608d3b0ec7a0b2fdc }

condition:
	$a0
}

        
