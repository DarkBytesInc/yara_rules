rule Win_Downloader_Banload_383
{
strings:
	$a0 = { 59c7c652a3371bb90dbb82551d842dea3c29e344e6ebf1c51d13b13c9a6510ef1fd0795346f0e7ebff26aed01a7f86753c7dde8ccd6e5d05cf0c1e4221f00c10b0e03e64b4ba424f9572bb920d9c31b51bfbd7bf20352db197df07364b012a3cb8c20d8fe0838e03b2 }

condition:
	$a0
}

        
