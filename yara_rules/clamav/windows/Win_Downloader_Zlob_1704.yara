rule Win_Downloader_Zlob_1704
{
strings:
	$a0 = { 6c6121e867a22a000a435dd9f235eb3d9aa517a3fd353dd6c64a0ce57f868f43eb84d814d2daba7858785b5a0ca438abf932ecf4d5b5425a3427a51ab89e9ab876dc1ab16bd43d4e88cd53a88b6d6d7389fcca12f81e6cc48192 }

condition:
	$a0
}

        
