rule Win_Downloader_Zlob_2278
{
strings:
	$a0 = { e5fe7bc40f9e68f302a1315d46cdf2b693f27b51405016d6d4f312976eddb8545ea8d06f661e3239aafff404c0ab0582ecae5873f83a49bc886713d86eb37b14e656cfb447aedd090e2f05965948d7ff055a06b7d3c472ff386d }

condition:
	$a0
}

        
