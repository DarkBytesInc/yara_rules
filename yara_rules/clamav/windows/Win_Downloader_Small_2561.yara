rule Win_Downloader_Small_2561
{
strings:
	$a0 = { 115589e580c59081ec9400000081ecfc0c000089e38925ca534000a12860400080e9ff8983580b0000a12c60400080ed }

condition:
	$a0
}

        
