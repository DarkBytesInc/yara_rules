rule Win_Downloader_1257_1
{
strings:
	$a0 = { b6ee8b45e43945e87502eb2f80eebc8b7de883c7048b078945e080e11d80e98c80ce778b45e43945e07502eb0e8b45e08945e880e26880c99bebd180eaee8b45e43945e87402eb09b800000000eb07eb058b45e8eb009d80ee3b5b80edeb5f80f6355ec9c2040080c9c055b20389 }

condition:
	$a0
}

        