rule Win_Downloader_Small_440
{
strings:
	$a0 = { 6f67732f73657276696365732e65786500000000ffffffff0b0000007477696e6b36342e65786500ffffffff0a000000686f737433322e6578650000ffffffff2e000000536f6674 }

condition:
	$a0
}

        