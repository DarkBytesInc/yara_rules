rule Win_Downloader_Banload_1637
{
strings:
	$a0 = { ffc00000ffff00000204b0ccdd75786e65f86bd072d102d2867729614639c5b2083244bc6c46f7f7ae03450e8b9a70a40898000fd7805dd5da04ab7eb5d665edb79d2ce9ea51c7fabbeb0c3db65618165f34d02a3da207bf29acb8bded13cb7be3f0163270de648c72f2ff }

condition:
	$a0
}

        
