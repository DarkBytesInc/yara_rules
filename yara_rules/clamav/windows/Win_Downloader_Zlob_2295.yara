rule Win_Downloader_Zlob_2295
{
strings:
	$a0 = { 50841a0cdf3a18e65f0151559af98bf34e1d0988bf09775dab9800fa9fc9bdb0a6d52614119bc5a6f5dc3c7d4663e8a64a16bbd74fcefc85a3be611c470b73e4665c45c72d92aa88157d59e819eda6329bb4747525b0f51ce0a4 }

condition:
	$a0
}

        
