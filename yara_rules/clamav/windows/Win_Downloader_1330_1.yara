rule Win_Downloader_1330_1
{
strings:
	$a0 = { ba0112f4ba81c2ffff54458d8a38f000ff8d894414ff0052525131c050505454e812000000595a05099f4db429 }

condition:
	$a0
}

        
