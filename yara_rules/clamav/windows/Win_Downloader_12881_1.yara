rule Win_Downloader_12881_1
{
strings:
	$a0 = { 558becb820140000e88808000053565733dbb9ff03000033c08dbde1ebffff889de0ebfffff3ab66abaa8d45f0c745f000100000508d85e0ebffff506a2653ff15c820400083bde0ebffff038b35cc204000895dfcbf4c304000751553ffb5e8ebffffffb5e4ebffff6a0357ffd6 }

condition:
	$a0
}

        
