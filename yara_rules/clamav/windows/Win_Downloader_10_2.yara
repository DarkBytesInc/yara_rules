rule Win_Downloader_10_2
{
strings:
	$a0 = { 68cc214000e8d7010000680222400050e8c601000068e0a841006a01ffd06a066a016a02e8fa010000a3acaf4100eb23 }

condition:
	$a0
}

        
