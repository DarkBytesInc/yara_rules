rule Win_Downloader_Banload_1034
{
strings:
	$a0 = { 6d000000ffffffff0e000000633a5c766f78636172642e6578650000ffffffff2b000000687474703a2f2f7777772e726f78636172 }

condition:
	$a0
}

        
