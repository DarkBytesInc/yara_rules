rule Win_Downloader_JS_41
{
strings:
	$a0 = { 6c616e67756167653d22656172746873696d756c61746f7222207372633d22687474703a2f2f71712e3232372e636e2f34333439383938382f6d6d2e657865223e }

condition:
	$a0
}

        