rule Win_Downloader_352_1
{
strings:
	$a0 = { bbd721400053c1fb02b83420400003d85b81eb1d204000b91d204000e8d4fcffff6834204000e8cc01000050e982010000 }

condition:
	$a0
}

        
