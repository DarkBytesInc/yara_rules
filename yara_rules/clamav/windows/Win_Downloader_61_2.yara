rule Win_Downloader_61_2
{
strings:
	$a0 = { 3de12140000074166a0068e1214000e82afeffff68ec224000e8fc0000006a0068de204000e814feffffe80a000000437265617465 }

condition:
	$a0
}

        
