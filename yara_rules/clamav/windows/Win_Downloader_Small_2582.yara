rule Win_Downloader_Small_2582
{
strings:
	$a0 = { 66550cef89e5048081ec9400000081ecfc0c0000248189e3b1eb892517504000a14860400080ccff8983c50b0000a14c }

condition:
	$a0
}

        
