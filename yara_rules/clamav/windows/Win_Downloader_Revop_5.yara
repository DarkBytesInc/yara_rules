rule Win_Downloader_Revop_5
{
strings:
	$a0 = { 746765656b2e636f6d2f7075702e6578650000000000000000000000633a5c50726f6772616d2046696c65735c6f7665722e65786500687474703a2f2f7265746172646564696e7465726e65746765 }

condition:
	$a0
}

        