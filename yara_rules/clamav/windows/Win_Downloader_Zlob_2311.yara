rule Win_Downloader_Zlob_2311
{
strings:
	$a0 = { ae6549eed6297aea1d67a74607337e494dea1dc396abdfd863e08c0a640caf2c778c675941c47fa34e06bf0b8fc1294e617de0656d19e813b4374ab94062338267a17fbacdfd22b347107a7e0a65 }

condition:
	$a0
}

        
