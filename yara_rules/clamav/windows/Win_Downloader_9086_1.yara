rule Win_Downloader_9086_1
{
strings:
	$a0 = { 8bd4a1a0401413e835fdffff8bf06a006a006a016a006a00680000004068ac381413e82efbffff8bd86a008d442408508b442408505653e891fbffff }

condition:
	$a0
}

        
