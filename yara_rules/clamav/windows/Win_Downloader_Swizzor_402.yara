rule Win_Downloader_Swizzor_402
{
strings:
	$a0 = { 73c1a861eaa6759bf6df3bd5ca8d6ace8b65d506095fd6c40136fb268983db9621d34b9b24f34dc6051f032145027ee67d60310bef86f53dc6dd7d12a4a0388625c4d75ad67653f3b0cf99abc373355954bbd0b5baba420ae927 }

condition:
	$a0
}

        
