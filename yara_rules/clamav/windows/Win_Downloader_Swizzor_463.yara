rule Win_Downloader_Swizzor_463
{
strings:
	$a0 = { 1ac93745736e78bbb124ffe359067aa744ed2666bb04757dcff1e590abd54a901a874be3cdd1441d4b223ab50fb04867e0c7b7b7b0ad90a369a08b18b7dec648c3aba3052b10218a18b08337f6395f4d3053821b1815afe62bc3 }

condition:
	$a0
}

        
