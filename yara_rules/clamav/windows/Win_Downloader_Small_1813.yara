rule Win_Downloader_Small_1813
{
strings:
	$a0 = { 837d0c01754068dc1500106a016a00e85c000000ff75088f0500300010a304300010e861000000 }

condition:
	$a0
}

        
