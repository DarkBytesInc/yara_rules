rule Win_Downloader_Banload_1541
{
strings:
	$a0 = { a41be57ed24d5049545e75623490b9f3ee0ccb22f61aa8440ed1fb506843f41d9c0d5d90ce1e3243764645bd7ec7f66e9195abcb2538f7caf98a1e126a85f69361c74f3a54a75d8d3ccacbca17b8dc4713f5bd09f486c7df76d2 }

condition:
	$a0
}

        
