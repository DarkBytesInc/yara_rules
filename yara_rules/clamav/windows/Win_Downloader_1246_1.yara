rule Win_Downloader_1246_1
{
strings:
	$a0 = { 8556feffff6880e681c68553feffff6480c59680c16cc68557feffff61c68559feffff54c68563feffff6580ea70c6855cfeffff7580e5d680e625c6855dfeffff6cb62880c1f2c6855ffeffff69c68558feffff7280e1ec80f60ac68555feffff4380e18ec6855afeffff6f80c9 }

condition:
	$a0
}

        
