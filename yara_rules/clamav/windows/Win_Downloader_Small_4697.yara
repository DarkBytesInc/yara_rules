rule Win_Downloader_Small_4697
{
strings:
	$a0 = { 70656e000000002e000000687474703a2f2f7777772e65726f6d656469612e6e6c2f6469616c65 }

condition:
	$a0
}

        
