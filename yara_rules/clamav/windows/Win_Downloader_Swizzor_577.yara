rule Win_Downloader_Swizzor_577
{
strings:
	$a0 = { e8eb1a61bf5d5593c98a92daae0c835f7c64c4cf9d7ba9753e23b2218ee7b450ae6b9141798ec80a48d18d6019fef6195afa9d650a0e31a60bd846f1848f4d88f6a6d1f95fda8a47d11834b44beaaa738f212ae64c679fc7a700089e3a5ad9d4ad5da642fe47b45d88 }

condition:
	$a0
}

        
