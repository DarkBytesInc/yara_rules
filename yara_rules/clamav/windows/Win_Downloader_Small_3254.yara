rule Win_Downloader_Small_3254
{
strings:
	$a0 = { 6a00ff35a8af4100e84402000083f80074e46a0068c8af4100506840224000ff35a8af4100e83f0200008b0dc8af4100bb40224000e807ffffffeb00 }

condition:
	$a0
}

        
