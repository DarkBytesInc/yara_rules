rule Win_Downloader_67632_1
{
strings:
	$a0 = { 535c73797374656d33325c47627053657276657233322e657865 }
	$a1 = { 5c57696e557064617465646174612e657865 }

condition:
	$a0 and $a1
}

        