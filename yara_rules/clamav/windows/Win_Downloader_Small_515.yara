rule Win_Downloader_Small_515
{
strings:
	$a0 = { 3a5c302e65786500633a5c312e65786500633a5c322e65786500633a5c332e65786500687474703a2f2f36 }

condition:
	$a0
}

        
