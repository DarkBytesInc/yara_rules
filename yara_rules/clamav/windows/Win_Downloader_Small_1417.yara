rule Win_Downloader_Small_1417
{
strings:
	$a0 = { 70747466696c6d732e636f6d2f646174612e65786500687474703a2f2f7777772e646d63656d61696c2e636f2e756b2f646174612e65786500687474703a2f2f7777772e7472656461676873696e676572732e6f72672f646174612e657865 }

condition:
	$a0
}

        