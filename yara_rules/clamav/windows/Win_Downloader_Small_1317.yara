rule Win_Downloader_Small_1317
{
strings:
	$a0 = { 703a712fee697a6703636f6e766572fb2e0e106d2f64ee699ebb94703424ab21335e4232bc31857a3f233dfd4273a87321707954f0612a73 }

condition:
	$a0
}

        
