rule Win_Downloader_Small_360
{
strings:
	$a0 = { 6aa00200609b2ccc0001e6ffffff5b496e7465726e657453686f72746375745d0d0a55524c3d00ff7fe4f74578706c0e2e646c687474703a2f2f68712d }

condition:
	$a0
}

        
