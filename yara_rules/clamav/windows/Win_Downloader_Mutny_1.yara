rule Win_Downloader_Mutny_1
{
strings:
	$a0 = { 610100006f010000000000006d61726e65742e75732f6d79676f6c642e657865000000000000000000000000 }

condition:
	$a0
}

        