rule Win_Downloader_Delf_1161
{
strings:
	$a0 = { 7b6f30782e6a1a5cab1b2c3441a9756dd2fd1caecc37d74b057bf1197dd5163ec1e4df29bf8055e1c83016846469dbab786c1440a8db7a973628867a8c1d40057976e1f0aa2ba085824246d8962f5f1fa6 }

condition:
	$a0
}

        
