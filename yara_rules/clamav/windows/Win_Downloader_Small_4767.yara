rule Win_Downloader_Small_4767
{
strings:
	$a0 = { 6a006a0068c630400068273040006a00ff15e03041006a0168c6304000e861000000c3 }

condition:
	$a0
}

        
