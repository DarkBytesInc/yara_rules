rule Win_Downloader_FraudLoad_32
{
strings:
	$a0 = { 55518d0c005957518d0c005933c0518d0c0059893424518d0c005989742404518d0c00596a30518d0c005958e9bc0600008d0c08e9ba06000083ec04518d0c005933c9518d0c005968a0af6b0c518d0c005968e8a9c9b1518d0c00596800000000518d0c00596851377db7518d0c005954518d0c00596830fc0700518d0c0059 }

condition:
	$a0
}

        