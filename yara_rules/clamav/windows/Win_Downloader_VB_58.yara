rule Win_Downloader_VB_58
{
strings:
	$a0 = { 771fb93c25076903466f726d65010e00ee6fffff416e6172636879205765622d644c00199b420022012306276b6cb3db }

condition:
	$a0
}

        
