rule Win_Downloader_13675_1
{
strings:
	$a0 = { 687474703a2f2f[0-80]433a5c57494e444f57535c[0-80]687474703a2f2f[0-80]433a5c57494e444f57535c }

condition:
	$a0
}

        
