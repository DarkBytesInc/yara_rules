rule Win_Downloader_Swizzor_578
{
strings:
	$a0 = { 7f80b88369eae1222da405694fcaeeec9b1a1d95898f01dad2030538db1ddd9b9c6c92f6e9b0cd7c26dbbb1678b2a497bf669a66506eefdddaed29a0ff7e860ae380970cbf05f6f10e6a19b701c71b6b8dfc1f953c30eb1c342a4b4e273057327b1de4065e510bc208 }

condition:
	$a0
}

        
