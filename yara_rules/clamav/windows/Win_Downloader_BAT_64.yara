rule Win_Downloader_BAT_64
{
strings:
	$a0 = { 6f70656e20[0-20]0d0a616e6f6e796d6f75730d0a62696e0d0a67657420 }
	$a1 = { 2e6578650d0a6279650d0a6f70656e20[0-20]0d0a616e6f6e796d6f75730d0a62696e0d0a67657420 }
	$a2 = { 2e657865 }

condition:
	$a0 and $a1 and $a2
}

        
