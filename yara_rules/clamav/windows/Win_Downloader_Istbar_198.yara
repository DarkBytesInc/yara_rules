rule Win_Downloader_Istbar_198
{
strings:
	$a0 = { 4b75656b75000000000000000000000000000000000050446d4e446932765873 }

condition:
	$a0
}

        
