rule Win_Downloader_Small_3177
{
strings:
	$a0 = { 6a006a00687a30400068123040006a00e83700000083f800750c6a00687a304000e81a000000 }

condition:
	$a0
}

        
