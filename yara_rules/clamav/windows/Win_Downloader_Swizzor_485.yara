rule Win_Downloader_Swizzor_485
{
strings:
	$a0 = { 294e55accc6bf6f4b4439d658e6ce34e237c4ce35a6f35c873382b44f89df68d5ec24afa3830e58aa84905e0d71d1f02c0ae02df82d12d8d200eeaf48f574b9605120031ffe358768a773df99437 }

condition:
	$a0
}

        
