rule Win_Downloader_12944_1
{
strings:
	$a0 = { 6a170000861700009c170000aa170000bc170000cc1700005c17000000000000????????29c0fec808c0740475f8eb67 }

condition:
	$a0
}

        
