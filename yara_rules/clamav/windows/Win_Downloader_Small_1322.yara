rule Win_Downloader_Small_1322
{
strings:
	$a0 = { 731c68656c405f7472617977386e64005553455233322e38444cf0a50155e3687488703a2fe2 }

condition:
	$a0
}

        
