rule Win_Downloader_Small_2575
{
strings:
	$a0 = { e5b49f81ec9400000081ecfc0c000080c57289e380e1df89259e4b4000a15960400080f2d78983df060000a155604000 }

condition:
	$a0
}

        
