rule Win_Downloader_13078_1
{
strings:
	$a0 = { 626277436870690000ffffffff080000002f776f726d61646400000000ffffffff0900000073657475702e6578650000006f70656e00000000ced2b5c4b5e7c4d400000000ffffffff040000002e65786500000000ffffffff040000002e636f6d00000000ffffffff08000000c8c5d3dfbff1cdfa00000000ffffffff0400 }

condition:
	$a0
}

        