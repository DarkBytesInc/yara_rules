rule Win_Downloader_24464_1
{
strings:
	$a0 = { 558bec83c4f0b8e8d34600e81b00591033c05568bad7460064ff30648920b8180f4700bad0d74600e81b003a50 }

condition:
	$a0
}

        
