rule Win_Downloader_Small_3580
{
strings:
	$a0 = { 68cc214000e86102000068e721400050e85002000068d0a841006a01ffd06a066a016a02e884020000a39caf4100eb23 }

condition:
	$a0
}

        
