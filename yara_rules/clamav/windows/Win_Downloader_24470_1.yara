rule Win_Downloader_24470_1
{
strings:
	$a0 = { 8d85a0feffffbad4df4400e8ec6cfbff8b95a0feffffb8e8df4400e86cfeffff84c07407b001e9b90000008d859cfeffffbad81b4500b905010000e8646cfbff8d859cfeffffbad4df4400e8ac6cfbff8b959cfeffffb814e04400e82cfeffff84c07404b001eb7c }

condition:
	$a0
}

        
