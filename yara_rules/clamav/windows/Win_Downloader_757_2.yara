rule Win_Downloader_757_2
{
strings:
	$a0 = { be674523018d3dff277f0281efff65290289fe8d9fc008fe7f81eb4404fe7f6a0089e25252526a006a00ff15f8c655005905f9df23bf0107c10f1083c7124f83 }

condition:
	$a0
}

        
