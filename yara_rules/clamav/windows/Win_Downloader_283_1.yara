rule Win_Downloader_283_1
{
strings:
	$a0 = { cc51030092879c81eef4cccaab23bd7ebb72b2d9be4db05fb0696278a916b4d3a822247ca136a4cb5a712e67a201d01e5b240af1567648774813592ec2c7273806ee6a79336af76fc31bdbd178cf }

condition:
	$a0
}

        
