rule Win_Downloader_Small_2051
{
strings:
	$a0 = { c64e8cdc1f0af019f8901a32a209fb22541b04ad44b31c1001f8305275041c687447703a2f1136342ecd32cf976733733530f07379 }

condition:
	$a0
}

        
