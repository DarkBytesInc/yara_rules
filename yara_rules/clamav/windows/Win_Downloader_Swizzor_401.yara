rule Win_Downloader_Swizzor_401
{
strings:
	$a0 = { 18b16081a6a44d4ec85e47dec59a123fbbca085267035a2e7cff922f5de35b816735be15db9868863844bd31aa280298323cd9ceeb4f878ff1d9dace61ce1d4bb0223fff0112a75fdc46cc13247fce3eb554b9702c4068cf9c40 }

condition:
	$a0
}

        
