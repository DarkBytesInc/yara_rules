rule Win_Downloader_Zlob_2277
{
strings:
	$a0 = { 1b0adf711bbcbec08ad9c79ce1e6fa7dca57bb316a905388666441fbc745b722925ea12ab84bbff95589f847e29de9626c9ce880e789dc66eb5907e29cdd0a99a44ca8e3a1839a9feccf01451721ad6e0e697dcd05ef63f17267 }

condition:
	$a0
}

        
