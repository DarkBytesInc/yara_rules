rule Win_Downloader_Small_2524
{
strings:
	$a0 = { e52c4181ec9400000081ecfc0c000089e389253b504000a1466040002cec89839a040000a14a60400080ca9a89838608 }

condition:
	$a0
}

        
