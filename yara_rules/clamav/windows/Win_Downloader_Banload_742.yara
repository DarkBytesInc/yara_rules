rule Win_Downloader_Banload_742
{
strings:
	$a0 = { 9c6367f1cdda506ba3b5c285e6cd1fe148ddb16eb5297ccd33666fa5c45c294dbd3ff49b5eb1babac78dbd234063790da001bbd04cb77f47423124ef0a6aee8089c29530e8ed2c57a4d14da4860a81d40a9b05365bf02c51c85b }

condition:
	$a0
}

        
