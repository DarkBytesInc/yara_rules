rule Win_Downloader_496_1
{
strings:
	$a0 = { 9cf452f5f22ef0ebb29f2d1d595a197024f6f69d4862c8b69d6c02edbfc3e72fef4b47b6edcd31cda60ceee567c6f16767693b3a31d9f2adeb49153490fda0ddda89aa803df8f5993c45c5b9ebaef92f61b66d4654d272c109b0e7b6d06033e2bad4b9aff9b64951f1e2d8b24f6dcf3c2bda5ed70e98b3 }

condition:
	$a0
}

        
