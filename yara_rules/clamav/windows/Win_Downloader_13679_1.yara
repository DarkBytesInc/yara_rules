rule Win_Downloader_13679_1
{
strings:
	$a0 = { 558bec83c4e833c08945e88945ecb830394000e84cfbffff33c05568f439400064ff3064892068003a40006a00e8a6fcffff8d4dec66badb01b80c3a4000e8d5fcffff8b45ece8f9fdffff8d4de866bacb0333c0e8 }

condition:
	$a0
}

        
