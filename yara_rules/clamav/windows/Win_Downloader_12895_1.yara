rule Win_Downloader_12895_1
{
strings:
	$a0 = { bb00000000682c434000e8??f3ffff6a006a006a036a006a006800000080684c434000e8??01000083f8ff7402eb01c3 }

condition:
	$a0
}

        
