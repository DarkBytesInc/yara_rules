rule Win_Downloader_Banload_1703
{
strings:
	$a0 = { 40c89e575d30eb775767d13b5a470a8983fe2c72f8256f1fe0507f0f512085405c4b0bd43bb7a9ac3fcbed8dcfafe0e3158ce6b13384fe7d09b099dba081f1e534ede221ca1b8df5c0522c95d03f16f2a4eb074703fc02c15dc8 }

condition:
	$a0
}

        
