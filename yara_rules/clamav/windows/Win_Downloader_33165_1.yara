rule Win_Downloader_33165_1
{
strings:
	$a0 = { 48747248744c48743a487428487416480f85??0100006a0abe[0-200]8bd08945088b423c }

condition:
	$a0
}

        
