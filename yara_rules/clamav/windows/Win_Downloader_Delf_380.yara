rule Win_Downloader_Delf_380
{
strings:
	$a0 = { 61666f746f733537322e7363720000538bd8c605d40b4500006a016a006a0068c0db440068f0db44008bc3e84b5afeff50e8a966fd }

condition:
	$a0
}

        
