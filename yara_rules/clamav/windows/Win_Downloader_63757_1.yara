rule Win_Downloader_63757_1
{
strings:
	$a0 = { 5589e583ec08c7042401000000ff }
	$a1 = { 433a5c57494e444f57535c73797374656d5c73797374656d33322e657865 }

condition:
	$a0 and $a1
}

        
