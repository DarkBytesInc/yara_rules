rule Win_Downloader_Adload_185
{
strings:
	$a0 = { f3ab8955c88955b88955b0899568ffffff899564ffffff899560ffffff89955cffffff89954cffffff89953cffffff89952cffffff89951cffffff89950cffffff8995fcfeffffbb??1c4000bf080000008d950cffffff8d4db88945e8899d14ffffff89bd0cffffffffd6 }

condition:
	$a0
}

        
