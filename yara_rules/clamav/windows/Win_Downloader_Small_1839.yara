rule Win_Downloader_Small_1839
{
strings:
	$a0 = { c645fc036a0168a814400068b4144000ff15281040006a0168c414400068d0144000ff1528104000 }

condition:
	$a0
}

        
