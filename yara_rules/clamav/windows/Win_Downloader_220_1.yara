rule Win_Downloader_220_1
{
strings:
	$a0 = { 9ca0c0002468b551a1cf7e384d88228a3caca8a7be95cf628d8d10342a1ec6d781afd47092df58a1463a7bba6c29b60ba622898f8131908fc76d37e22d0fb47df4f018d0d42adabcf9903e1f3604d98399c6fc0dd8 }

condition:
	$a0
}

        
