rule Win_Downloader_5650_1
{
strings:
	$a0 = { 595dc300ffffffff14000000633a5c77696e646f77735c77696e33322e65786500000000ffffffff26000000687474 }

condition:
	$a0
}

        
