rule Win_Downloader_Small_3360
{
strings:
	$a0 = { 444f57535c73797374656d33325c7376636834622e6578650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 }

condition:
	$a0
}

        