rule Win_Downloader_Zlob_1513
{
strings:
	$a0 = { d0872f9941c325067e9d0c95565e3bb73117a7b2076efd1b05c1ba89530f562f2f3b717cca6bdb662db9afb4fc7c5634547c3b61e0d9cd9b8f3da8d8febaa912d212e4aa9e896822616d1ffec3bb27748528f488c6 }

condition:
	$a0
}

        
