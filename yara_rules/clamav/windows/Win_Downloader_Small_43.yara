rule Win_Downloader_Small_43
{
strings:
	$a0 = { 33efb610b66553bb6c69732e746df7ffdbff7000687474703a2f2f77002e33757a2e6e65742f76322f6999bffdbbfb2e706870e72f2564876f66747756655c4d }

condition:
	$a0
}

        
