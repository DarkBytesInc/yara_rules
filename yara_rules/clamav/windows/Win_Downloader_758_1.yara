rule Win_Downloader_758_1
{
strings:
	$a0 = { be674523018d3dff177f0281efff65290289fe8d9fc008fe7f81eb4404fe7f6a0089e25252526a006a00ff15f8b655005905f9df23bf0107c10f1083c7124f83 }

condition:
	$a0
}

        
