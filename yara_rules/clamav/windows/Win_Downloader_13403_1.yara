rule Win_Downloader_13403_1
{
strings:
	$a0 = { 433a5c57696e646f77735c[0-50]687474703a2f2f[0-50]433a5c57696e646f77735c[0-50]687474703a2f2f }

condition:
	$a0
}

        
