rule Win_Downloader_24583_1
{
strings:
	$a0 = { 929290565058905e909087d287d29090bf101040009087fa87fa87dbbe1317400087fb87fb9090 }

condition:
	$a0
}

        
