rule Win_Downloader_913_1
{
strings:
	$a0 = { be674523018d3dff076a0281efff65290289fe8d9fc008fe7f81eb4404fe7f6a0089e25252526a006a00ff15f8a640005905f9df23bf0107c10f1083c7124f83ef0d39df7ed9ffd6baba06a6bf38e9a8 }

condition:
	$a0
}

        
