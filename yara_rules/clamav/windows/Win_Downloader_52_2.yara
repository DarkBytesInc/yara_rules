rule Win_Downloader_52_2
{
strings:
	$a0 = { 81f4138bf69399201c7012972359d2d0d490a01fbe83c80b5955f8197cd924d7f7948f69ebf38c98992e37b690019b49ab2e548a8095f0e4809773ae8fcaa924196a680a401e1086d77fa361007ed5087c5a6db257 }

condition:
	$a0
}

        