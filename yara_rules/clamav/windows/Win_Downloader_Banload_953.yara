rule Win_Downloader_Banload_953
{
strings:
	$a0 = { 3231382f6d736e6d67722e73637200000000633a5c57696e646f77735c72656773657276652e6578 }

condition:
	$a0
}

        
