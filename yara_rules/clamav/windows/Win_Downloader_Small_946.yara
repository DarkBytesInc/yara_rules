rule Win_Downloader_Small_946
{
strings:
	$a0 = { 1eab697747dca1d3bc9ec3b7ec8d0201d2402540af1e777f1791888e31fe207d9eb3d256961a0fe994fe97dfde82c12da01935d4b6ef6a761b7b0519d89dddfd98cd5875bffff13566668078666436 }

condition:
	$a0
}

        
