rule Win_Downloader_Small_5396
{
strings:
	$a0 = { 68fde03a2fe2380e312e39357d4c343608307f37296175b3211c5933c7f87375743b726151e3f46367ea3f1f362670311c }

condition:
	$a0
}

        
