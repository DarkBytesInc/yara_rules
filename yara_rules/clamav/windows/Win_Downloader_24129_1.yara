rule Win_Downloader_24129_1
{
strings:
	$a0 = { 8798b0649a26a314ee70cb759a74f161710c9b64f154639176cf4440fc590ecb38301c8fc5c7f304ecf0e42ccfcfcfdcd0c8c087e579bebcb8b42c1b3e2db03f703d511ec7e13f71266c0bb1c5362e6d736e360b0019007264732e7961686f6f42b1a8e367676ca95683e576332e6d423be69e7468ae880ebf63de75e573ce771decc19386b365787f955b8a636cf68db45a2c12f8 }

condition:
	$a0
}

        