rule Win_Downloader_Delf_1339
{
strings:
	$a0 = { 408d7d01f491d2ac5221a044ddd918687772a2e77e16f77e1ce77e437f290b5ec817baf6c16f320f5aec179640b57646948445b9b2253083533608b9235e336414c82d1c9a0ae68379c923d7b22bd7b006db82dccec6f75ceffffffe3eff7f7f7cf9e7df9f3ef9f7e7ddf3f1dfd3fbdff8e504ddbd8420383fcf4fcf2fd8d7e777ee89f83e0fade83edae77a }

condition:
	$a0
}

        