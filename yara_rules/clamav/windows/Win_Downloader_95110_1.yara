rule Win_Downloader_95110_1
{
strings:
	$a0 = { 558bec6aff68b040400068ec25400064a100000000506489250000000083ec585356578965e8ff153c4040 }

condition:
	$a0
}

        