rule Win_Downloader_Small_2720
{
strings:
	$a0 = { 684d144000ff15c4134000a3951650006a006a006a006a006826144000ff3595165000ff15c8134000 }

condition:
	$a0
}

        
