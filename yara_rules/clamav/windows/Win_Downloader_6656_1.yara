rule Win_Downloader_6656_1
{
strings:
	$a0 = { 010000000000006d61726174686f6e6565722e6e65742f6d792e65786500 }

condition:
	$a0
}

        
