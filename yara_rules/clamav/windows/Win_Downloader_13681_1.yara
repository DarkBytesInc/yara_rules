rule Win_Downloader_13681_1
{
strings:
	$a0 = { 558bec83c4ec53565733c08945ecb81c6e4100e840eafeffbbecb8410033c055683570410064ff30648920b84c704100e873fdffffb84c704100e8 }

condition:
	$a0
}

        
