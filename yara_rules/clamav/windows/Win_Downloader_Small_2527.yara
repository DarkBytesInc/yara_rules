rule Win_Downloader_Small_2527
{
strings:
	$a0 = { 55b49e89e580c25b81ec9400000081ecfc0c000080ca8b89e38925e6534000a14c6040008983e20a0000a14860400080 }

condition:
	$a0
}

        
