rule Win_Downloader_Small_428
{
strings:
	$a0 = { 3c170000000000000000000000000000000000006e7470332e657865000000006e6f74657061642e657865005c0000006b6c6d6e30393831000000007769303339382e6578650000687474703a2f2f6170 }

condition:
	$a0
}

        