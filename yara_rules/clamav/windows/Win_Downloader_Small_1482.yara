rule Win_Downloader_Small_1482
{
strings:
	$a0 = { 31c00fefe40fd524240f6f1c240fe9dc0f7f1c248b042485c074e531c0e8000000005a83ea2281ea4080000081c20092000052c20000 }

condition:
	$a0
}

        
