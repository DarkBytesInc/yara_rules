rule Win_Downloader_Small_1963
{
strings:
	$a0 = { 6899914100e84c2e00008945e08b7de0ff37e83f2e00008945e066c745e402006835820000e8082e0000 }

condition:
	$a0
}

        
