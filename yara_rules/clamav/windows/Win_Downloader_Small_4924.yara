rule Win_Downloader_Small_4924
{
strings:
	$a0 = { 680813400051b9a83a4000e8650700008b15b03a400068dc12400052b9a83a4000e84f070000 }

condition:
	$a0
}

        
