rule Win_Downloader_Small_3472
{
strings:
	$a0 = { e7f2f09672faffe44f98cdf23413baa443e7b2c2ac04bc0e4b53b30c9ba05c1adaedea815edf8b4c56f3becae5c2d43c5853a4a7e522f467a85ec5eaf03df43b4020312fa82699fe3a361a8090f3821f859218db4088456df5db6a2454013490ccdc1b1b }

condition:
	$a0
}

        
