rule Win_Downloader_FraudLoad_31
{
strings:
	$a0 = { 55518d0c005957518d0c005933c0518d0c0059893424518d0c005989742404518d0c00596a30518d0c005958e9080200008104244223fe76e90202000083ec04518d0c005933c9518d0c0059689e0e2d50518d0c005968927b78ed518d0c00596800000000518d0c0059683aabd64f518d0c005954518d0c00596830920a0051 }

condition:
	$a0
}

        