rule Win_Downloader_25912_1
{
strings:
	$a0 = { 505159905890909292575058905f87cb87cb90bf0e1040009096969292be17174000 }

condition:
	$a0
}

        
