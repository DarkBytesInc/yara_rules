rule Win_Downloader_63732_1
{
strings:
	$a0 = { b800000000600bc07468e8000000005805530000008038e9751361eb45db2d375048 }

condition:
	$a0
}

        
