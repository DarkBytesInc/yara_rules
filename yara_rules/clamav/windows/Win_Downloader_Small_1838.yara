rule Win_Downloader_Small_1838
{
strings:
	$a0 = { 6d006f7574706f73742e657865006c73706669782e65786500007a6c636c69656e742e6578 }

condition:
	$a0
}

        
