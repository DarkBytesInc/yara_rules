rule Win_Downloader_Zlob_2275
{
strings:
	$a0 = { b26e91da1272cbc14ca7c91741b9fb813031b092cfbadddfd2afec19e6ab5180e1deb4e38e193bd762d943c7d071395d0a6771497dcc83f9f2592ce3c85739403612384a203be77b6ae9bdda55a8ec512257da59c899b4eea22d }

condition:
	$a0
}

        
