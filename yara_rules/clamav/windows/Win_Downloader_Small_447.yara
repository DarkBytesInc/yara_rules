rule Win_Downloader_Small_447
{
strings:
	$a0 = { 586a046a0050e8c2000000c9c300006b6a6e757761653062736b666400687474703a2f2f6e6f6e73746f }

condition:
	$a0
}

        
