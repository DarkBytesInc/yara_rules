rule Win_Downloader_Small_310
{
strings:
	$a0 = { 444044c04545110870c44503958c024b00ae927a14a235b35c76d5ea6f687474703a2f2f41c8632e063457add0cd0b21ab565ffd2e636f6d2fbb77a43e6ab2fa7f2f }

condition:
	$a0
}

        
