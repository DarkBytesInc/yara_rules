rule Win_Downloader_Small_905
{
strings:
	$a0 = { 0fb745d4eb0e803e2076d84689758cebf56a0a5850565353ff15f452400050e80200001589459850ff15c85340008b45ec8b088b09 }

condition:
	$a0
}

        
