rule Win_Downloader_Dadobra_238
{
strings:
	$a0 = { 9dcdeaafa5139ee4055242f475e1cac86ff31d6732faf1500f659ca29623cb312036da47ded392ba9af15b286f32b9af9bb3607b629d062449fb81f13bbe465f721696a4b99a3b997610541f1ac89f9cb92123269a }

condition:
	$a0
}

        
