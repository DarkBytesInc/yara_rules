rule Win_Downloader_Small_736
{
strings:
	$a0 = { 30400033c05a59596489106800114000c3e98affffffebf85dc38bc0832d1c30400001c3687474703a2f2f7777772e3531742e63 }

condition:
	$a0
}

        
