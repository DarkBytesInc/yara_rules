rule Win_Downloader_Apropo_10
{
strings:
	$a0 = { 6f706f735c436c69656e7400414d00004170726f706f73436c69656e74000000312e302e3130 }

condition:
	$a0
}

        
