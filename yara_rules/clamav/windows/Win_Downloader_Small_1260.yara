rule Win_Downloader_Small_1260
{
strings:
	$a0 = { 6a006a006a006a006a006a00a154664000506a00ba1c494000b814494000b900000080e845f3ffff8bd868284940006aff6a00e8a5f2ffff8bf8e8c6f2ffff3db7000000750de85aebffff57e87cf2ffffeb16 }

condition:
	$a0
}

        
