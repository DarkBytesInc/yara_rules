rule Win_Downloader_Small_2525
{
strings:
	$a0 = { e581ec9400000081ecfc0c000089e380ed3f8925ad4c4000a13d604000898306080000a1396040002c2e8983ff020000 }

condition:
	$a0
}

        
