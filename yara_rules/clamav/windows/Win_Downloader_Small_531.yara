rule Win_Downloader_Small_531
{
strings:
	$a0 = { 6d697261636c652e636f6d2f70726f746563746f722e6578650000633a5c70726f7461732e657865000000687474703a2f2f696e7374 }

condition:
	$a0
}

        