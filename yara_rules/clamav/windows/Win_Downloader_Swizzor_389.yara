rule Win_Downloader_Swizzor_389
{
strings:
	$a0 = { d4fda7bb2a94ea9e91141354c9e3881ce6f802fb0feb449468b73d323d8fc335d817574850d9feddea22c1b12d3c37cb1b96d1714077edea035a4cdc83b896c7d136db94ec607a67efbe36a22dfd7ff479f101087286c43569f3 }

condition:
	$a0
}

        
