rule Win_Downloader_Swizzor_488
{
strings:
	$a0 = { 37c9f9c6f619514a6e8046c0db7d5d13817a1f86245af322684cd2a29df19d5a6a7bced66e6aa461aa723106df6c31aebe5b80992883301aef1e66001f08f3c6d5067074400e3c6d4c5867484fed }

condition:
	$a0
}

        
