rule Win_Downloader_887_1
{
strings:
	$a0 = { 12c5241741cb4eaed427189cd72dc320a4f8e6f1c5a8b09d487f22c87f9b978ec1bac53f7c96a58dbac06e13f2aafbdaf4ba105532d9d87950f7f35440285746460bf65a77504646bacbfdf6595c93dbecaed13b34083a0cc767bef7 }

condition:
	$a0
}

        
