rule Win_Downloader_33166_1
{
strings:
	$a0 = { 48747248744c48743a487428487416480f85??0100006a0abe[0-250]6a0abe??334000566800304000 }

condition:
	$a0
}

        
