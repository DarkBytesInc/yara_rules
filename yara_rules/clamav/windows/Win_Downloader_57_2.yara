rule Win_Downloader_57_2
{
strings:
	$a0 = { 476a0068eca941006a0157ff35e8a94100e8220100003bfb75e6ff35e8a94100e8bf0000006a0168d0a84100e801010000 }

condition:
	$a0
}

        
