rule Win_Downloader_481_1
{
strings:
	$a0 = { c3f59f0ff2773a11055e125b8f338b7edd0ff37f9dc2a31b848e4763b13967217ace37a7986856eb768744346c23206024de3de3a47e6ab1b7be10f07af3faefd4d1e0ad6041a4b3fca6ad997e20 }

condition:
	$a0
}

        
