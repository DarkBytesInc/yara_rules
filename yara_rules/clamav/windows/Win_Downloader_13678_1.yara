rule Win_Downloader_13678_1
{
strings:
	$a0 = { 558bec83c4f0b89c344000e8d4fdffff68283540006a00e834ffffff6a006a00685c35400068783540006a00e817ffffff6a05685c354000e8 }

condition:
	$a0
}

        
