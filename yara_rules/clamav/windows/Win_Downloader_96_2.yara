rule Win_Downloader_96_2
{
strings:
	$a0 = { c78524ffffff001d4000c7851cffffff08000000ffd78b068d8d4cffffff8d955cffffff515256ff90000700008d950cffffff8d8d3cffffffc78514ffffff84224000c7850cffffff08000000ffd78b068d8d2cffffff8d953cffffff }

condition:
	$a0
}

        
