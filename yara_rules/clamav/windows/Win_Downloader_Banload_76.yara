rule Win_Downloader_Banload_76
{
strings:
	$a0 = { 83e80272337437eb473d960000c07f1174352d930000c07428487413487416eb2f2dfd0000c07425 }
	$a1 = { ffffff090000005c637372732e736372 }

condition:
	$a0 and $a1
}

        
