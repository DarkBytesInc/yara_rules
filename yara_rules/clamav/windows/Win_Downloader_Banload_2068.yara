rule Win_Downloader_Banload_2068
{
strings:
	$a0 = { 3cc8d764ebff412ed0da450b2c54027f09739d03a24a2a87315992434731c86fb1497e54feb5cd1a3cf17f23d2493f043be2ab92515d1f5cfd01046336cc707775e9497d8fad1c8e4dc0c6d4173d30b1 }

condition:
	$a0
}

        
