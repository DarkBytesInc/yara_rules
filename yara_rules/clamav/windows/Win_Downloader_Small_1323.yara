rule Win_Downloader_Small_1323
{
strings:
	$a0 = { 6a006a006851111413681e1114136a00e84b0100006a006851111413e8270100006a00e8f600 }

condition:
	$a0
}

        
