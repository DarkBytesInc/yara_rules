rule Win_Downloader_912_1
{
strings:
	$a0 = { b9cbacc0f381c13565880c518d99b016440081eb3412440051b9f816490089e2526a006a006a006a00ff115905f9df23 }

condition:
	$a0
}

        
