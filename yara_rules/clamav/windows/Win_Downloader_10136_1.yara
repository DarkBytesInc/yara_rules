rule Win_Downloader_10136_1
{
strings:
	$a0 = { 558bec83c4e833c08945e88945ecb8e4384000e898fbffff33c05568a839400064ff3064892068b43940006a00e8f2fcffff8d4dec66bafd02b8c0394000e821fdffff }

condition:
	$a0
}

        
