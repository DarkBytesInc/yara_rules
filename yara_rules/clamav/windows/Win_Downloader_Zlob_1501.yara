rule Win_Downloader_Zlob_1501
{
strings:
	$a0 = { 04a001c58fc0f255546dee5c3965b89444f216f24d8ab73b327926b16dcccb8bb6a3d4aaefcc9f25c92599754dd83f28722ffcaaf218c7ae5a3af550d4d0980fdf4b0ac02ffac90260995b666de4fe707c0d9cf2362a }

condition:
	$a0
}

        
