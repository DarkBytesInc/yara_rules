rule Win_Downloader_Small_1203
{
strings:
	$a0 = { 240b00002e006d6f6e0075727683bec900546f80e0b0816f776e6c0055524c0000000000000000 }

condition:
	$a0
}

        
